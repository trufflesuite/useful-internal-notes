//SPDX-License-Identifier: MIT

pragma solidity ^0.8.7;

//a library that provides access to all standard precompiles.
//even the identity.
//no using Solidity builtin precompiles here; the point of this
//library is to do all the marshalling and unmarshalling manually
//(because, well, I want to).
//(OK, I can make use of the ABI encode/decode functions, but no
//*unsual* marshalling or unmarshalling can be done manually.)

//this is not meant for actual use.
//this is viewly an exercise in marshalling and unmarshalling.
//I'll do this in Solidity where I can but drop into
//assembly where I need to.
//(Yeah, by doing it in Solidity I'm letting it do some
//of the work for me, but not much.)

//NOTE: OK actually I'm too lazy to do the assembly, so I'm
//marking these functions view rather than pure.  Sorry.
//It's just an exercise anyway.
//(Similarly, I'm not bothering with an inclusive pragma up top.)

//Note if I write "marshalling: none" or "unmarshalling: none",
//I'm excluding the implicit conversion between Solidity bytestrings
//and raw bytestrings.  Indeed I ignore that in all
//marshalling and unmarshalling descriptions.

//similarly the marshalling/unmarshalling descriptions on the uint256
//overload for #5 just describe marshalling/unmarshalling for the
//bytes overload, not for the precompile itself.

//ABI choices:
//1. 512-bit integers will be given as uint256[2] (little-endian)
//2. 1024-bit integers will be given as uint256[4] (little-endian)
//3. Pairs of these will be given as a struct I define below
//4. Arbitrarily large integers will be given as bytes (big-endian), but
//for precompiles that take these (currently: just #5)
//I will also make an interface that takes uint256
//5. all of these will revert on error, even if the precompile doesn't
//6. modexp will also revert if modulus is zero
//7. For how I'm doing ecrecover, see below
//8. For how I'm doing blake2_F, see below
//Obviously, these are not always the ways to save gas (particularly
//my choice to use little-endian), but whatever.

//to avoid compiler warnings, we always include a require(status) line,
//even when status should never be false
//(OK, technically status could still end up false if we overflowed the
//EVM call stack, but I'm not counting that)
library PrecompileLibrary {

  struct AltBn128Pair {
    uint256[2] g1;
    uint256[4] g2;
  }

  //#1
  function ecrecover(bytes32 hash, uint8 v, uint256 r, uint256 s) public view returns (address) {
    //marshal: pad v and concatenate
    bytes memory marshalled = abi.encode(hash, v, r, s);
    (bool status, bytes memory raw) = address(1).staticcall(marshalled);
    require(status); //should never fire; we get raw.length == 0 instead on error
    //unmarshal: extract address from last 20 bytes of returned word
    return abi.decode(raw, (address)); //will revert if raw.length == 0
  }

  //#2
  function sha256(bytes memory input) public view returns (bytes32) {
    //marshalling: none
    (bool status, bytes memory raw) = address(2).staticcall(input);
    require(status); //should never fire (doesn't make sense)
    //unmarshal: it's just the returned word
    return abi.decode(raw, (bytes32));
  }

  //#3
  function ripemd160(bytes memory input) public view returns (bytes20) {
    //marshalling: none
    (bool status, bytes memory raw) = address(3).staticcall(input);
    require(status); //should never fire (doesn't make sense)
    //unmarshal: extract result from last 20 bytes of returned word
    return bytes20(abi.decode(raw, (uint160)));
  }

  //#4
  function identity(bytes memory input) public view returns (bytes memory) {
    //marshalling: none
    (bool status, bytes memory result) = address(4).staticcall(input);
    require(status); //should never fire (doesn't make sense)
    //unmarshalling: none
    return result;
  }

  //#5
  function modexp(bytes memory base, bytes memory exponent, bytes memory modulus) public view returns (bytes memory) {
    //require nonzero modulus
    bool nonzeroModulus = false;
    for (uint256 i = 0; i < modulus.length; i++) {
      if (modulus[i] != 0x00) {
        nonzeroModulus = true;
        break;
      }
    }
    require(nonzeroModulus);
    //marshal: put lengths first, as 256-bit integers, then the bytestrings
    bytes memory marshalled = abi.encodePacked(base.length, exponent.length, modulus.length, base, exponent, modulus);
    (bool status, bytes memory result) = address(5).staticcall(marshalled);
    require(status); //should never fire (input is automatically zero-padded, and returns 0 on zero modulus; plus we've set things up right and checked for zero modulus)
    //unmarshalling: none
    return result;
  }

  //#5 (again)
  function modexp(uint256 base, uint256 exponent, uint256 modulus) public view returns (uint256) {
    require(modulus != 0); //technically redundant but I think useful to skip encoding in this case
    //marshal: encode to bytes
    bytes memory raw = modexp(abi.encode(base), abi.encode(exponent), abi.encode(modulus));
    //unmarshal: left-pad to 32 bytes, then convert to integer
    //(we can't just decode, as we may have raw.length < 32)
    bytes32 padded; //starts out as zero
    for (uint8 i = 0; i < 32; i++) {
      //Solidity won't let us just set individual bytes in a bytes32,
      //have to use bit operations instead
      padded |= bytes32(raw[raw.length - 1 - i]) >> ((31 - i) * 8);
    }
    return uint256(padded);
  }

  //#6
  function alt_bn128_add(uint256[2] memory x, uint256[2] memory y) public view returns (uint256[2] memory) {
    //marshal: convert to big endian and concatenate
    bytes memory marshalled = abi.encodePacked(x[1], x[0], y[1], y[0]);
    (bool status, bytes memory raw) = address(6).staticcall(marshalled);
    require(status); //may actually fire
    //unmarshal: convert from big endian
    uint256[2] memory bigEndian = abi.decode(raw, (uint256[2]));
    return [bigEndian[1], bigEndian[0]];
  }

  //#7
  function alt_bn128_mul(uint256[2] memory x, uint256 s) public view returns (uint256[2] memory) {
    //marshal: convert to big endian and concatenate
    bytes memory marshalled = abi.encodePacked(x[1], x[0], s);
    (bool status, bytes memory raw) = address(7).staticcall(marshalled);
    require(status); //may actually fire
    //unmarshal: convert from big endian
    uint256[2] memory bigEndian = abi.decode(raw, (uint256[2]));
    return [bigEndian[1], bigEndian[0]];
  }

  //#8
  function alt_bn128_pair(AltBn128Pair[] memory pairs) public view returns (bool) {
    //marshal: convert to big endian and concatenate
    //note encodePacked can't handle structs, so we convert each to an array instead
    uint256[6][] memory bigEndian = new uint256[6][](pairs.length);
    for (uint256 i = 0; i < pairs.length; i++) {
      bigEndian[i] = [
        pairs[i].g1[1], pairs[i].g1[0],
        pairs[i].g2[3], pairs[i].g2[2], pairs[i].g2[1], pairs[i].g2[0]
      ];
    }
    bytes memory marshalled = abi.encodePacked(bigEndian);
    (bool status, bytes memory raw) = address(8).staticcall(marshalled);
    require(status); //may actually fire
    //unmarshal: get the bool from last byte of returned word
    return abi.decode(raw, (bool));
  }

  //#9
  function blake2_F(uint32 rounds, bytes8[8] memory h, bytes8[16] memory m, bytes8[2] memory t, bool f) public view returns (bytes8[8] memory) {
    //marshal: just concatenate
    //note that encodePacked does *not* pack array elements, so we need to expand this out.
    //However, we can't *just* expand it out directly and stick it all in encodePacked,
    //because the stack can't handle that.  So we'll group things up first.
    bytes memory hConcatenated = bytes.concat(h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    bytes memory mConcatenatedPart1 = bytes.concat(m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]);
    bytes memory mConcatenatedPart2 = bytes.concat(m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15]);
    bytes memory marshalled = abi.encodePacked(rounds, hConcatenated, mConcatenatedPart1, mConcatenatedPart2, t[0], t[1], f);
    (bool status, bytes memory raw) = address(9).staticcall(marshalled);
    require(status); //may fire in general, but never should here since we've set things up right
    //unmarshal: split up 64 bytes into 8 individual bytes8s
    //unfortunately abi.decode can't handle this sort of packed decoding
    bytes32[2] memory grouped = abi.decode(raw, (bytes32[2])); //easiest way to get 64 bytes in manipulable form
    bytes8[8] memory result;
    for(uint8 i = 0; i < 8; i++) {
      bytes32 window = bytes32(bytes8(type(uint64).max)); //this will right-pad
      //extract correct part, shift it back to the left, then truncate
      result[i] = bytes8((grouped[i / 4] & (window >> ((i % 4) * 64))) << ((i % 4) * 64));
    }
    return result;
  }
}
