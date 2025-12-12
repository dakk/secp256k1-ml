open Secp256k1
open Utils

(* Helper to create test secret key from known good bytes *)
let test_secret_key ctx =
  let seckey = buffer_of_hex "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530" in
  Key.read_sk_exn ctx seckey

(* Helper to create test public key *)
let test_public_key ctx =
  let sec = test_secret_key ctx in
  Key.neuterize_exn ctx sec

let test_schnorr_of_bytes () =
  let ctx = Context.create [Sign; Verify] in
  let kp = Keypair.create_exn ctx (test_secret_key ctx) in
  let msg = buffer_of_hex "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in
  let sign = Schnorr.sign32 ctx msg kp None in 
  let ver = Schnorr.verify ctx sign msg (Keypair.xonly_pub_exn ctx kp) in
  assert ver

let test_schnorr =
  [
    ("schnorr_of_bytes", `Quick, test_schnorr_of_bytes);
  ]
