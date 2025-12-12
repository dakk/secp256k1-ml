let () =
  Alcotest.run "secp256k1" [
    "basic", Test_basic.test_basic;
    "schnorr", Test_schnorr.test_schnorr;
  ]