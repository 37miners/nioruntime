// Copyright (c) 2022, 37 Miners, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::cell::CellBody;
use crate::cell::{Cell, Certs, NetInfo};
use crate::ed25519;
use crate::ed25519::Ed25519Identity;
use crate::rsa::RsaCrosscert;
use crate::types::{ChannelContext, ChannelDestination, TorState, Verifier};
use crate::util::x509_extract_rsa_subject_kludge;
use crate::util::ExternallySigned;
use crate::util::Timebound;
use nioruntime_deps::arrayref::array_ref;
use nioruntime_deps::rustls::{ClientConfig, ClientConnection, Reader, RootCertStore, Writer};
use nioruntime_deps::sha2::{Digest, Sha256};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::convert::TryInto;
use std::io::{Read, Write};
use std::sync::Arc;

info!();

/// our protocol version
const VERSIONS_MSG: &[u8] = &[0, 0, 7, 0, 2, 0, 4];

pub struct Channel {
	tls_conn: ClientConnection,
	destination: ChannelDestination,
	verified: bool,
	versions_confirmed: bool,
	remote_certs: Option<Certs>,
	remote_net_info: Option<NetInfo>,
}

impl Channel {
	pub fn new(destination: ChannelDestination) -> Result<Self, Error> {
		let config = Self::make_config()?;
		// tor doesn't use dns so use localhost.
		let tls_conn = ClientConnection::new(config, "localhost".try_into()?)?;
		let verified = false;
		let versions_confirmed = false;
		let remote_certs = None;
		let remote_net_info = None;

		Ok(Self {
			destination,
			tls_conn,
			verified,
			versions_confirmed,
			remote_certs,
			remote_net_info,
		})
	}

	pub fn is_verified(&self) -> bool {
		self.verified
	}

	pub fn start(&mut self) -> Result<(), Error> {
		self.tls_conn.writer().write_all(VERSIONS_MSG)?;
		Ok(())
	}

	pub fn writer(&mut self) -> Writer {
		self.tls_conn.writer()
	}

	pub fn read_tor(&mut self, rd: &mut dyn Read) -> Result<usize, Error> {
		self.tls_conn.read_tls(rd).map_err(|e| {
			let error: Error =
				ErrorKind::Tor(format!("tls_conn.read_tls generated error: {}", e)).into();
			error
		})
	}

	pub fn send_cell(&mut self, cell: Cell) -> Result<(), Error> {
		if !self.verified {
			return Err(
				ErrorKind::Tor(format!("Channel must be verified before sending cells.")).into(),
			);
		}
		let mut writer = self.writer();
		let bytes = cell.serialize()?;
		debug!("sending cell = {:?}", bytes)?;
		writer.write(&bytes)?;
		Ok(())
	}

	pub fn write_tor(&mut self, wr: &mut dyn Write) -> Result<usize, Error> {
		self.tls_conn.write_tls(wr).map_err(|e| {
			let error: Error =
				ErrorKind::Tor(format!("tls_conn.write_tls generated error: {}", e)).into();
			error
		})
	}

	pub fn process_packets(&mut self, ctx: &mut ChannelContext) -> Result<TorState, Error> {
		let io_state = self.tls_conn.process_new_packets().map_err(|e| {
			let error: Error =
				ErrorKind::Tor(format!("process_new_packets generated error: {}", e)).into();
			error
		});

		match io_state {
			Ok(io_state) => {
				if io_state.peer_has_closed() {
					Ok(io_state.into())
				} else {
					let wlen = io_state.tls_bytes_to_write();
					let cells = self.process_next_cell(io_state.plaintext_bytes_to_read(), ctx)?;

					Ok(TorState::new(wlen, cells, false))
				}
			}

			Err(e) => Err(e),
		}
	}

	fn reader(&mut self) -> Reader {
		self.tls_conn.reader()
	}

	fn process_next_cell(
		&mut self,
		len: usize,
		ctx: &mut ChannelContext,
	) -> Result<Vec<Cell>, Error> {
		let mut ret = vec![];
		debug!("process unverified with bytes to read: {}", len)?;
		if len > 0 {
			let mut reader = self.reader();
			let buf = &mut ctx.in_buf;
			if buf.len() < len + ctx.offset {
				buf.resize(len + ctx.offset, 0u8);
			}
			reader.read_exact(&mut buf[ctx.offset..])?;

			debug!(
				"process_next_cell (len={}): '{:?}'",
				len,
				&buf[ctx.offset..]
			)?;

			ctx.offset += len;

			if !self.versions_confirmed {
				self.confirm_versions(ctx)?;
			}

			if self.versions_confirmed {
				loop {
					match self.process_cell(ctx)? {
						Some(cell) => match cell.body() {
							CellBody::NetInfo(net_info) => {
								debug!("got a netinfo")?;
								self.remote_net_info = Some(net_info.to_owned());
							}
							CellBody::Certs(certs) => {
								debug!("got a certs")?;
								self.remote_certs = Some(certs.to_owned());
							}
							CellBody::AuthChallenge(_) => {
								debug!("got an auth challenge")?;
							}
							CellBody::Padding(_) => {
								debug!("got padding")?;
							}
							CellBody::Created2(_) => {
								ret.push(cell);
							}
							CellBody::Relay(_) => {
								ret.push(cell);
							}
							CellBody::Create2(_) => {
								return Err(ErrorKind::Tor(format!(
									"Got unexpected create2 cell as a client!"
								))
								.into());
							}
							CellBody::Extend2(_) => {
								return Err(ErrorKind::Tor(format!(
									"Got unexpected extend2 cell as a client!"
								))
								.into());
							}
						},
						None => {
							debug!("got a none")?;
							break;
						}
					}

					if self.remote_certs.is_some()
						&& self.remote_net_info.is_some()
						&& !self.verified
					{
						self.verify_channel()?;
						self.verified = true;
					}
				}
			}
		}
		Ok(ret)
	}

	// Verify the channel
	fn verify_channel(&self) -> Result<(), Error> {
		let certs = match &self.remote_certs {
			Some(certs) => certs,
			None => return Err(ErrorKind::Tor(format!("no certs")).into()),
		};

		let mut type2_cert = None;
		let mut type4_cert = None;
		let mut type5_cert = None;
		let mut type7_cert = None;
		for cert in &certs.certs {
			debug!("parsing cert type = {}", cert.cert_type)?;

			if cert.cert_type == 2 {
				if type2_cert.is_some() {
					return Err(ErrorKind::Tor(
						"certs must have exactly 1 type 2 cert".to_string(),
					)
					.into());
				}
				type2_cert = Some(cert.cert.clone());
			} else if cert.cert_type == 4 {
				if type4_cert.is_some() {
					return Err(ErrorKind::Tor(
						"certs must have exactly 1 type 4 cert".to_string(),
					)
					.into());
				}
				type4_cert = Some(ed25519::Ed25519Cert::decode(&cert.cert)?);
			} else if cert.cert_type == 5 {
				if type5_cert.is_some() {
					return Err(ErrorKind::Tor(
						"certs must have exactly 1 type 5 cert".to_string(),
					)
					.into());
				}
				type5_cert = Some(ed25519::Ed25519Cert::decode(&cert.cert)?);
			} else if cert.cert_type == 7 {
				if type7_cert.is_some() {
					return Err(ErrorKind::Tor(
						"certs must have exactly 1 type 7 cert".to_string(),
					)
					.into());
				}
				type7_cert = Some(cert.cert.clone());
			}
		}

		let type2_cert = match type2_cert {
			Some(type2_cert) => type2_cert,
			None => {
				return Err(
					ErrorKind::Tor("certs must have exactly 1 type 2 cert".to_string()).into(),
				)
			}
		};

		let type7_cert = match type7_cert {
			Some(type7_cert) => type7_cert,
			None => {
				return Err(
					ErrorKind::Tor("certs must have exactly 1 type 7 cert".to_string()).into(),
				)
			}
		};

		let id_sk = match type4_cert {
			Some(type4_cert) => type4_cert,
			None => {
				return Err(
					ErrorKind::Tor("certs must have exactly 1 type 4 cert".to_string()).into(),
				)
			}
		};
		let sk_tls = match type5_cert {
			Some(type5_cert) => type5_cert,
			None => {
				return Err(
					ErrorKind::Tor("certs must have exactly 1 type 5 cert".to_string()).into(),
				)
			}
		};

		let mut sigs = Vec::new();
		let now = std::time::SystemTime::now();

		// Part 1: validate ed25519 stuff.
		// Check the identity->signing cert
		let (id_sk, id_sk_sig) = id_sk.check_key(&None)?.dangerously_split()?;
		sigs.push(&id_sk_sig);
		let id_sk = id_sk.check_valid_at_opt(Some(now)).map_err(|_| {
			let error: Error = ErrorKind::Tor("Certificate expired or not yet valid".into()).into();
			error
		})?;

		// Take the identity key from the identity->signing cert
		let identity_key = id_sk.signing_key().ok_or_else(|| {
			let error: Error =
				ErrorKind::Tor("Missing identity key in identity->signing cert".into()).into();
			error
		})?;

		// Take the signing key from the identity->signing cert
		let signing_key = id_sk.subject_key().as_ed25519().ok_or_else(|| {
			let error: Error =
				ErrorKind::Tor("Bad key type in identity->signing cert".into()).into();
			error
		})?;

		// Now look at the signing->TLS cert and check it against the
		// peer certificate.
		let (sk_tls, sk_tls_sig) = sk_tls
			.check_key(&Some(*signing_key))? // TODO(nickm): this is a bad interface
			.dangerously_split()?;
		sigs.push(&sk_tls_sig);
		let sk_tls = sk_tls.check_valid_at_opt(Some(now)).map_err(|_| {
			let error: Error = ErrorKind::Tor("Certificate expired or not yet valid".into()).into();
			error
		})?;

		let peer_certs = self.tls_conn.peer_certificates();
		let peer_certs = match peer_certs {
			Some(peer_certs) => peer_certs,
			None => {
				return Err(ErrorKind::Tor("Peer does not have a TLS cert".into()).into());
			}
		};
		if peer_certs.len() == 0 {
			return Err(ErrorKind::Tor("Peer does not have a cert".into()).into());
		}

		// get the peer certificate which is first per rustls docs.
		let peer_cert = &peer_certs[0].0;
		let peer_cert_sha256 = Sha256::digest(peer_cert);
		let peer_cert_sha256 = &peer_cert_sha256[..];

		if peer_cert_sha256 != sk_tls.subject_key().as_bytes() {
			return Err(ErrorKind::Tor("Peer cert did not authenticate TLS cert".into()).into());
		}

		// Batch-verify the ed25519 certificates in this handshake.
		//
		// In theory we could build a list of _all_ the certificates here
		// and call pk::validate_all_sigs() instead, but that doesn't gain
		// any performance.
		if !ed25519::validate_batch(&sigs[..]) {
			return Err(ErrorKind::Tor("Invalid ed25519 signature in handshake".into()).into());
		}

		let ed25519_id: Ed25519Identity = identity_key.into();

		// Part 2: validate rsa stuff.

		// What is the RSA identity key, according to the X.509 certificate
		// in which it is self-signed?
		//
		// (We don't actually check this self-signed certificate, and we use
		// a kludge to extract the RSA key)
		let pkrsa = x509_extract_rsa_subject_kludge(&type2_cert).ok_or({
			let error: Error = ErrorKind::Tor("could not extract RSA Identity key".into()).into();
			error
		})?;

		// Now verify the RSA identity -> Ed Identity crosscert.
		//
		// This proves that the RSA key vouches for the Ed key.  Note that
		// the Ed key does not vouch for the RSA key: The RSA key is too
		// weak.
		let rsa_cert = RsaCrosscert::decode(&type7_cert)?
			.check_signature(&pkrsa)
			.map_err(|_| {
				let error: Error = ErrorKind::Tor("Bad RSA->Ed crosscert signature".into()).into();
				error
			})?
			.check_valid_at_opt(Some(now))
			.map_err(|_| {
				let error: Error =
					ErrorKind::Tor("RSA->Ed crosscert expired or invalid".into()).into();
				error
			})?;

		if !rsa_cert.subject_key_matches(identity_key) {
			return Err(ErrorKind::Tor("RSA->Ed crosscert certifies incorrect key".into()).into());
		}

		let rsa_id = pkrsa.to_rsa_identity();

		// check this is who we expected
		if rsa_id != self.destination.rsa_identity {
			return Err(ErrorKind::Tor(format!(
				"Unexpected rsa_id. Expected: {}, Found: {}.",
				self.destination.rsa_identity, rsa_id,
			))
			.into());
		}

		if ed25519_id != self.destination.ed_identity {
			return Err(ErrorKind::Tor(format!(
				"Unexpected ed25519 id. Expected: {}, Found: {}",
				self.destination.ed_identity, ed25519_id
			))
			.into());
		}

		debug!(
			"Validated identity as {:?} [{}], {:?}, rsa_id.to_strinpped_base64={:?}, rsa_bytes={:?}, ecdsa_bytes={:?}",
			nioruntime_deps::base64::encode(Sha256::digest(ed25519_id.as_bytes())),
			rsa_id,
			ed25519_id,
			rsa_id.to_stripped_base64(),
			rsa_id.as_bytes(),
			ed25519_id.as_bytes(),
		)?;

		// all checks passed. We're ok which will mark the channel as verified
		Ok(())
	}

	fn confirm_versions(&mut self, ctx: &mut ChannelContext) -> Result<(), Error> {
		if ctx.offset < 5 {
			// not enough data yet. Return ok and process again when more.
			return Ok(());
		}

		if ctx.in_buf[0] != 0 || ctx.in_buf[1] != 0 || ctx.in_buf[2] != 7 {
			return Err(ErrorKind::Tor("TOR must start with 007".to_string()).into());
		}

		let len = u16::from_be_bytes(*array_ref![ctx.in_buf, 3, 2]);
		if ctx.offset < (len + 5).into() {
			// not enough data yet. Return ok and process again when more.
			return Ok(());
		}

		let mut found = false;
		for i in 0..(len / 2) {
			match ctx.in_buf[(6 + i * 2) as usize] {
				4 => found = true,
				_ => {}
			}
		}
		if !found {
			return Err(ErrorKind::Tor("Protocol version 4 not supported".to_string()).into());
		}

		self.versions_confirmed = true;
		debug!("versions confirmed!")?;
		let dr_len: usize = (len + 5).into();
		ctx.in_buf.drain(..dr_len);
		ctx.offset = ctx.offset.saturating_sub(dr_len);

		Ok(())
	}

	fn process_cell(&mut self, ctx: &mut ChannelContext) -> Result<Option<Cell>, Error> {
		debug!("process cell with offset = {}", ctx.offset)?;
		Cell::next(ctx)
	}

	fn make_config() -> Result<Arc<ClientConfig>, Error> {
		let root_store = RootCertStore::empty();

		let mut config = ClientConfig::builder()
			.with_safe_default_cipher_suites()
			.with_safe_default_kx_groups()
			.with_safe_default_protocol_versions()?
			.with_root_certificates(root_store)
			.with_no_client_auth();

		config
			.dangerous()
			.set_certificate_verifier(std::sync::Arc::new(Verifier {}));

		Ok(Arc::new(config))
	}
}

#[cfg(test)]
mod test {
	use crate::cell::Create2;
	use crate::cell::Extend2;
	use crate::channel::Channel;
	use crate::channel::NetInfo;
	use crate::channel::{Cell, CellBody};
	use crate::constants::*;
	use crate::ed25519::Ed25519Identity;
	use crate::ed25519::XDalekPublicKey as PublicKey;
	use crate::handshake::ntor::NtorClient;
	use crate::handshake::ClientHandshake;
	use crate::rsa::RsaIdentity;
	use crate::types::ChannelContext;
	use crate::types::ChannelDestination;
	use crate::util::tor1::ClientLayer;
	use crate::util::tor1::CryptInit;
	use crate::util::RngCompatExt;
	use crate::util::Tor1RelayCrypto;
	use nioruntime_deps::base64;
	use nioruntime_deps::hex;
	use nioruntime_deps::rand;
	use nioruntime_deps::rand::Rng;
	use nioruntime_err::{Error, ErrorKind};
	use nioruntime_log::*;
	use nioruntime_util::lockr;
	use std::convert::TryInto;
	use std::io::Read;
	use std::io::Write;
	use std::net::IpAddr;
	use std::net::TcpStream;
	use std::time::Instant;

	info!();

	//#[test]
	fn _test_channel() -> Result<(), Error> {
		let now = Instant::now();
		let mut wbuf = vec![];

		/*
		let ed_bytes = base64::decode("5IpiwC9CSzIYZF8vYfsYGF+DvlTm0jPBATT6jhCu0Nw=")?;
		let rsa_bytes = nioruntime_deps::hex::decode("90F5CAA5C17C3DB7AC305922DD24E1DC2796E11E")?;
		let mut ntor_onion_bytes: [u8; 32] = [0u8; 32];
		let ip = "127.0.0.1";
		let addr = format!("{}:9001", ip);
				*/

		/*
		// http://154.35.175.225/tor/status-vote/current/authority
		//
		// r Serge ukSoieZLk/qisRTgLConmoVVxTM q4hCVnq2s5RVEcJp9YwlFtrqxQg 2022-07-28
		// 17:50:04 66.111.2.131 9001 9030
		// a [2610:1c0:0:5::131]:9001
		// s Authority Running Stable V2Dir Valid
		// v Tor 0.4.7.8
		// pr Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2
		// Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
		// w Bandwidth=102 Measured=41
		// p reject 1-65535
		// id ed25519 HymdZCakUvsQMKzuBkx9z1yv80GMifRMXyNG6biXrwA
		// stats wfu=1.000000 tk=14724748 mtbf=14724748
		// m 28,29 sha256=PCoPGNB0inD3S1XIUslSxso5coRKw4X7egNCrkBcARM
		// m 30,31,32 sha256=ixPpwymlWxEoepVy6l8GFvoB8en4VguKliX1hCYmxCg
		let ed_bytes = base64::decode("HymdZCakUvsQMKzuBkx9z1yv80GMifRMXyNG6biXrwA=")?;
		let ip = "66.111.2.131";
		let addr = format!("{}:9001", ip);
		let rsa_bytes = base64::decode("ukSoieZLk/qisRTgLConmoVVxTM=")?;

		// http://154.35.175.225/tor/micro/d/PCoPGNB0inD3S1XIUslSxso5coRKw4X7egNCrkBcARM
		// (see m line in previous paste)
		// onion-key
		// -----BEGIN RSA PUBLIC KEY-----
		// MIGJAoGBAOiyeVp5PW5OLItPC1tZkOAQbQ+zt2h/pmD+DOOgNOQQgAvypwfpSODA
		// w1E2j0sCJa217ZUEahZlHPaAPcB0J1xm9ysExkoWQe5/9kR3tt2M2IiYUISeOrNa
		// sKslHen977EYr64kbe6YUw6Qw1ba4S6VnYEdYgPrVWcjA9t1xTUbAgMBAAE=
		// -----END RSA PUBLIC KEY-----
		// ntor-onion-key 2E5pgIfV1UTNj7eOpZTzuUCIlTLM1h8jaafrIeIQaiw=
		// family $3F092986E9B87D3FDA09B71FA3A602378285C77A
		// $BA44A889E64B93FAA2B114E02C2A279A8555C533
		// $D317C7889162E9EC4A1DA1A1095C2A0F377536D9
		// id ed25519 HymdZCakUvsQMKzuBkx9z1yv80GMifRMXyNG6biXrwA
		let mut ntor_onion_bytes: [u8; 32] = [0u8; 32];
		ntor_onion_bytes
			.clone_from_slice(&base64::decode("2E5pgIfV1UTNj7eOpZTzuUCIlTLM1h8jaafrIeIQaiw=")?[..]);

		let ip2 = "45.66.33.45";
		let addr2 = format!("{}:443", ip2);
		let ed_bytes2 = base64::decode("g/2ajydWM/x16QePc6QXMVcVsaftXbmH4dZUozDhl5E")?;
		let rsa_bytes2 = base64::decode("fqbq1v2DCDxTj0QDi7+gd1h911U")?;
		let mut ntor_onion_bytes2: [u8; 32] = [0u8; 32];
		ntor_onion_bytes2
			.clone_from_slice(&base64::decode("z4l44BO46IkwQHF62Owsxh+fMlzF1lMXIy648TyhaQg=")?[..]);

		let ip3 = "140.78.100.42";
		let addr3 = format!("{}:8443", ip3);
		let ed_bytes3 = base64::decode("euqiwTENP+vaxdPjjD1OFH5n0oMaM/o3Me1Q+moi4zo")?;
		let rsa_bytes3 = base64::decode("AIGW3ESUgsc8+pcSRFIjkX92CSE")?;
		let mut ntor_onion_bytes3: [u8; 32] = [0u8; 32];
		ntor_onion_bytes3
			.clone_from_slice(&base64::decode("9vXnGeOeUWWMCAXkDiRyM4n/z4q9/xojAERivdd+qHE=")?[..]);
				*/

		// use a local setup for testing
		let ip = "127.0.0.1";
		let addr = format!("{}:39001", ip);
		let ed_bytes = base64::decode("Z9aVaImseaOHcmqF8PYjPRvRtsoNRkgMfVunFQUDTag=")?;
		let rsa_bytes: [u8; 20] =
			hex::decode("BF6F607DB0E5AD64ADBC18D6467AB028D521A6FE")?[..].try_into()?;
		let mut ntor_onion_bytes: [u8; 32] = [0u8; 32];
		ntor_onion_bytes
			.clone_from_slice(&base64::decode("PtfQsnnCPPA93X3BcbFeCxGMLDfVfIG4XbzVCIlOsgU=")?[..]);

		let addr2 = format!("{}:39002", ip);
		let ed_bytes2 = base64::decode("8nf9qPZ9gixbks0KrZEiLsKJYyVmmAgZUAW/iYvGnKI=")?;
		let rsa_bytes2: [u8; 20] =
			hex::decode("9093FA181B5620F0C6CD05892E92C0EEA5B633DA")?[..].try_into()?;
		let mut ntor_onion_bytes2: [u8; 32] = [0u8; 32];
		ntor_onion_bytes2
			.clone_from_slice(&base64::decode("l7BJm4Cq3c8YJlq/H+vaUtdaJ4K7lsDEmqv8ZI3HUjo=")?[..]);

		let addr3 = format!("{}:39003", ip);
		let ed_bytes3 = base64::decode("Z9aVaImseaOHcmqF8PYjPRvRtsoNRkgMfVunFQUDTag=")?;
		let rsa_bytes3: [u8; 20] =
			hex::decode("C74E8194DDFA0A14EA77D36A79BDB9A346F27342")?[..].try_into()?;
		let mut ntor_onion_bytes3: [u8; 32] = [0u8; 32];
		ntor_onion_bytes3
			.clone_from_slice(&base64::decode("zoxann7++99ntL8gQThK4IJPiKU+XOOhTihl3pIDa04=")?[..]);

		let dest1 = ChannelDestination {
			sockaddrs: vec![addr.clone()],
			ed_identity: Ed25519Identity::from_bytes(&ed_bytes).unwrap(),
			rsa_identity: RsaIdentity::from_bytes(&rsa_bytes).unwrap(),
			ntor_onion_pubkey: PublicKey::from(ntor_onion_bytes),
		};

		let dest2 = ChannelDestination {
			sockaddrs: vec![addr2.clone()],
			ed_identity: Ed25519Identity::from_bytes(&ed_bytes2).unwrap(),
			rsa_identity: RsaIdentity::from_bytes(&rsa_bytes2).unwrap(),
			ntor_onion_pubkey: PublicKey::from(ntor_onion_bytes2),
		};

		let dest3 = ChannelDestination {
			sockaddrs: vec![addr3.clone()],
			ed_identity: Ed25519Identity::from_bytes(&ed_bytes3).unwrap(),
			rsa_identity: RsaIdentity::from_bytes(&rsa_bytes3).unwrap(),
			ntor_onion_pubkey: PublicKey::from(ntor_onion_bytes3),
		};

		info!(
			"dest1 = {:?}, dest2 = {:?}, dest3 = {:?}",
			dest1, dest2, dest3
		)?;

		let mut channel = Channel::new(dest1.clone())?;
		channel.start()?;

		channel.write_tor(&mut wbuf)?;
		let mut stream = TcpStream::connect(addr)?;
		stream.write(&wbuf)?;

		let mut buffer: Vec<u8> = vec![];
		buffer.resize(1024 * 1024, 0u8);
		let mut ctx = ChannelContext::new();
		let mut sent_extend2 = false;
		let mut sent_extend2_2 = false;
		let mut sent_create2 = false;
		let crypt_state = ctx.crypt_state.clone();
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let mut channel_id: u32 = rng.gen();
		channel_id |= 0x80000000;

		debug!("about to start channel {}", channel_id)?;
		loop {
			let mut wbuf = vec![];
			if buffer.len() != 1024 * 1024 {
				buffer.resize(1024 * 1024, 0u8);
			}

			let len = stream.read(&mut buffer[..])?;
			debug!("read len = {} bytes", len)?;
			if len == 0 {
				break;
			}

			channel.read_tor(&mut &buffer[0..len])?;

			debug!("about to process packets")?;
			match channel.process_packets(&mut ctx) {
				Ok(tor_state) => {
					let cells = tor_state.cells();
					let verified = channel.is_verified();
					debug!(
						"processing a tor_state with {} cells. Elapsed={:?}. IsVerified={}",
						cells.len(),
						now.elapsed(),
						channel.is_verified(),
					)?;
					for cell in cells {
						info!("Got a cell: {:?}", cell)?;
						match cell.body() {
							CellBody::Created2(created2) => {
								let crypt_state_clone = crypt_state.clone();
								let mut crypt_state = lockw!(crypt_state_clone)?;
								match &crypt_state.hs_state {
									Some(state) => {
										let hsdata = created2.get_hsdata();
										debug!("hsdata = {}", hsdata.len())?;
										let generator = NtorClient::client2(state.clone(), hsdata)?;
										let pair = Tor1RelayCrypto::construct(generator).unwrap();
										let (outbound, inbound) = pair.split();
										crypt_state.cc_out.add_layer(Box::new(outbound));
										crypt_state.cc_in.add_layer(Box::new(inbound));
										debug!("created2 on circ id = {}", cell.circ_id())?;
									}
									None => {
										error!("expected a build state")?;
									}
								}
							}
							CellBody::Relay(relay) => {
								let cmd = relay.get_relay_cmd();
								debug!("Got a relay cell with cmd = {}", cmd)?;

								match cmd {
									RELAY_CMD_EXTENDED2 => {
										info!("got an extended2 cell")?;
										let crypt_state_clone = crypt_state.clone();
										let mut crypt_state = lockw!(crypt_state_clone)?;
										match &crypt_state.hs_state {
											Some(state) => {
												let hsdata = &relay.get_relay_data()[2..];
												debug!("hsdata.len={}", hsdata.len())?;
												let generator =
													NtorClient::client2(state.clone(), hsdata)?;
												let pair =
													Tor1RelayCrypto::construct(generator).unwrap();
												let (outbound, inbound) = pair.split();
												crypt_state.cc_out.add_layer(Box::new(outbound));
												crypt_state.cc_in.add_layer(Box::new(inbound));
												debug!(
													"extended2 on circ id = {}, layers = {}",
													cell.circ_id(),
													crypt_state.layers(),
												)?;
											}
											None => {
												error!("expected a build state")?;
											}
										}
									}
									_ => {
										todo!()
									}
								}
							}
							_ => {}
						}
					}

					if !verified {
						// we don't do anything if we're not verified
					} else {
						let layers = lockr!(crypt_state)?.layers();
						info!("layers={}, elapsed=[{}]", layers, now.elapsed().as_millis())?;
						if layers == 0 && !sent_create2 {
							// send a netinfo cell
							channel.send_cell(Cell::new(
								0,
								CellBody::NetInfo(NetInfo::new(
									IpAddr::V4(ip.parse()?),
									vec![IpAddr::V4("127.0.0.1".parse()?)],
								)?),
							)?)?;

							channel.send_cell(Cell::new(
								channel_id,
								CellBody::Create2(Create2::new(&dest1, &crypt_state)),
							)?)?;
							sent_create2 = true;
						} else if layers == 1 && !sent_extend2 {
							// we have received our created2 cell.
							// send an extend2 cell
							channel.send_cell(Cell::new(
								channel_id,
								CellBody::Extend2(Extend2::new(&dest2, &crypt_state)),
							)?)?;
							sent_extend2 = true;
						} else if layers == 2 && !sent_extend2_2 {
							// we are ready for the third and final hop
							channel.send_cell(Cell::new(
								channel_id,
								CellBody::Extend2(Extend2::new(&dest3, &crypt_state)),
							)?)?;
							sent_extend2_2 = true;
						} else if layers == 3 {
							// test complete, circuit built
							return Ok(());
						}
					}
				}
				Err(e) => {
					error!("Error processing packets: {}", e)?;
					return Err(ErrorKind::ApplicationError(format!(
						"Error processing packets: {}",
						e
					))
					.into());
				}
			}

			channel.write_tor(&mut wbuf)?;

			if wbuf.len() > 0 {
				debug!(
					"writing {} bytes to the channel [elapsed={}]",
					wbuf.len(),
					now.elapsed().as_millis()
				)?;
				stream.write(&wbuf)?;
			}
		}

		Ok(())
	}
}
