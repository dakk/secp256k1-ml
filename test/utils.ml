let buffer_of_hex s =
  let { Cstruct.buffer; _ } = Hex.to_cstruct (`Hex s) in
  buffer

let cstruct_testable =
  Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

let assert_eq_cstruct a b =
  let a = Cstruct.of_bigarray a in
  let b = Cstruct.of_bigarray b in
  assert (Alcotest.equal cstruct_testable a b)