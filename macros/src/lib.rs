// Copyright 2022 37 Miners, LLC
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

#[proc_macro_derive(Ser)]
pub fn derive_ser(strm: TokenStream) -> TokenStream {
	let mut found_struct = false;
	let mut readable = "".to_string();
	let mut writeable = "".to_string();
	for item in strm {
		match item {
			Ident(ident) => {
				if found_struct {
					readable = format!(
						"impl nioruntime_util::ser::Readable for {} {{\n\
						fn read<R: nioruntime_util::ser::Reader>(\n\
							reader: &mut R\n\
						) -> Result<Self, Error> {{\n\
							Ok(Self {{\n",
						ident
					);
					writeable = format!(
						"impl nioruntime_util::ser::Writeable for {} {{\n\
						fn write<W: nioruntime_util::ser::Writer>(\n\
							&self,\n\
							writer: &mut W\n\
						) -> Result<(), nioruntime_err::Error> {{",
						ident
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

				for item in group.stream() {
					match &item {
						Ident(ident) => {
							if id.is_none() {
								id = Some(ident.to_string());
							} else {
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
									}
									_ => {}
								}

								id = None;
							}
						}
						Group(_group) => {}
						Punct(_punct) => {}
						Literal(_literal) => {}
					}
				}
			}
			_ => {}
		}
	}

	writeable = format!(
		"{}\n\
		Ok(())\n\
	}} }}",
		writeable
	);

	readable = format!(
		"{}\n\
		}})}} }}",
		readable
	);

	let ret = format!("{}{}", readable, writeable,);

	ret.parse().unwrap()
}
