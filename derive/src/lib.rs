// Copyright (c) 2022, 37 Miners, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate proc_macro;
use proc_macro::TokenStream;
use proc_macro::TokenTree::{Group, Ident, Literal, Punct};

// Don't see a way to get code coverage on macros with tarpaulin so disabling. Some tests use this
// code though.
#[proc_macro_derive(Serializable)]
#[cfg(not(tarpaulin_include))]
pub fn derive_serializable(strm: TokenStream) -> TokenStream {
	let mut found_struct = false;
	let mut readable = "".to_string();
	let mut writeable = "".to_string();
	let mut group_item_count = 0;
	for item in strm {
		match item {
			Ident(ident) => {
				if found_struct {
					readable = format!(
						"impl nioruntime_util::ser::Serializable for {} {{\n\
						fn read<R: nioruntime_util::ser::Reader>(\n\
							reader: &mut R\n\
						) -> Result<Self, Error> {{\n\
							Ok(Self {{\n",
						ident
					);
					writeable = format!(
						//"impl nioruntime_util::ser::Writeable for {} {{\n\
						"fn write<W: nioruntime_util::ser::Writer>(\n\
							&self,\n\
							writer: &mut W\n\
						) -> Result<(), nioruntime_err::Error> {{",
					);
				} else if ident.to_string() == "struct" {
					found_struct = true;
				} else {
					found_struct = false;
				}
			}
			Group(group) => {
				found_struct = false;

				let mut id: Option<String> = None;
				let mut skip = false;

				let mut items = vec![];
				for item in group.stream() {
					items.push(item);
				}
				group_item_count = items.len();
				let mut i = 0;
				loop {
					if i >= items.len() {
						break;
					}
					let item = &items[i];
					i += 1;
					match item {
						Ident(ident) => {
							if &ident.to_string()[..] == "pub" {
								continue;
							}
							if id.is_none() && !skip {
								id = Some(ident.to_string());
							} else if id.is_some() {
								let field_id = id.unwrap();
								let ident = &ident.to_string()[..];
								match ident {
									"u8" | "u16" | "u32" | "u64" | "u128" | "i8" | "i16"
									| "i32" | "i64" | "i128" => {
										writeable = format!(
											"{}\n\
											writer.write_{}(self.{})?;",
											writeable, ident, field_id
										);
										readable = format!(
											"{}\n\
											{}: reader.read_{}()?,",
											readable, field_id, ident
										);
										skip = false;
									}
									"bool" => {
										writeable = format!(
                                                                                        "{}\n\
                                                                                        writer.write_u8(match self.{} {{ true => 1, false => 0}})?;",
                                                                                        writeable, field_id
                                                                                );
										readable = format!(
                                                                                        "{}\n\
                                                                                        {}: match reader.read_u8()? {{ 0 => false, _ => true }},",
                                                                                        readable, field_id
                                                                                );
										skip = false;
									}
									"Vec" => {
										writeable = format!(
											"{}\n\
											nioruntime_util::ser::Serializable::write(&self.{}, writer)?;",
											writeable, field_id,
										);
										readable = format!(
											"{}\n\
											{}: {{\n\
												let l = reader.read_u64()?;\n\
												let mut v = vec![];\n\
												for _ in 0..l {{\n\
													v.push(nioruntime_util::ser::Serializable::read(reader)?);\n\
												}}\n\
												v\n\
											}},",
											readable, field_id
										);
										skip = true;
									}
									"Option" => {
										writeable = format!(
                                                                                        "{}\n\
                                                                                        match &self.{} {{\n\
												Some(x) => {{\n\
													writer.write_u8(1)?;\n\
													nioruntime_util::ser::Serializable::write(&x, writer)?;\n\
												}},\n\
												None => writer.write_u8(0)?,\n\
											}}",
											writeable, field_id
                                                                                );
										readable = format!(
                                                                                        "{}\n\
                                                                                        {}: match reader.read_u8()? {{\n\
												0 => None,\n\
												_ => Some(nioruntime_util::ser::Serializable::read(reader)?),\n\
                                                                                        }},",
                                                                                        readable, field_id
                                                                                );
										skip = true;
									}
									_ => {
										writeable = format!(
											"{}\n\
											nioruntime_util::ser::Serializable::write(&self.{}, writer)?;",
											writeable, field_id
										);
										readable = format!(
											"{}\n\
											{}: nioruntime_util::ser::Serializable::read(reader)?,",
											readable, field_id
										);
										skip = false;
									}
								}

								id = None;
							} else {
								if &ident.to_string()[..] != "Vec"
									&& &ident.to_string()[..] != "Option"
								{
									skip = false;
								}
							}
						}
						Group(group) => {
							let stream = group.stream();
							let mut items = vec![];
							for item in stream {
								items.push(item);
							}
							if items.len() == 3 {
								if items[1].to_string() == ";" {
									let field_id = id.unwrap();
									let len: usize = items[2].to_string().parse().unwrap();
									readable = format!(
										"{}\n\
										{}: [",
										readable, field_id,
									);
									for i in 0..len {
										writeable = format!(
											"{}\n\
											nioruntime_util::ser::Serializable::write(&self.{}[{}], writer)?;",
											writeable, field_id, i
										);
										readable = format!(
											"{}\n\
											nioruntime_util::ser::Serializable::read(reader)?,",
											readable
										);
									}

									readable = format!(
										"{}\n\
										],",
										readable
									);
									id = None;
								}
							}
						}
						Punct(_punct) => {}
						Literal(_literal) => {}
					}
				}
			}
			_ => {}
		}
	}

	if group_item_count == 1 {
		writeable = format!(
			"{}\n\
			nioruntime_util::ser::Serializable::write(&self.0, writer)?;",
			writeable
		);
		readable = format!(
			"{}\n\
			0: nioruntime_util::ser::Serializable::read(reader)?,",
			readable
		);
	}

	writeable = format!(
		"{}\n\
		Ok(())\n\
	}} }}",
		writeable
	);

	readable = format!(
		"{}\n\
		}})}}",
		readable
	);

	let ret = format!("{}{}", readable, writeable,);
	ret.parse().unwrap()
}
