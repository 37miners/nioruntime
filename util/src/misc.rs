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
//

pub fn invert_timestamp128(timestamp: u128) -> u128 {
	u128::MAX.saturating_sub(timestamp)
}

pub fn invert_timestamp64(timestamp: u64) -> u64 {
	u64::MAX.saturating_sub(timestamp)
}

#[cfg(test)]
mod test {
	use crate::misc::*;
	use nioruntime_err::Error;

	#[test]
	fn test_invert() -> Result<(), Error> {
		for i in 0..1024 {
			let x_u128: u128 = i as u128;
			assert_eq!(x_u128, invert_timestamp128(invert_timestamp128(x_u128)));
			let x_u64: u64 = i as u64;
			assert_eq!(x_u64, invert_timestamp64(invert_timestamp64(x_u64)));
			assert!(x_u128 < invert_timestamp128(x_u128));
			assert!(x_u64 < invert_timestamp64(x_u64));
		}

		Ok(())
	}
}
