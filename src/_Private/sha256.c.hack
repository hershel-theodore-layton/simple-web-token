/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\_Private;

use namespace HH\Lib\{C, Math, Str, Vec};
use function chr, ord;

function sha256_pure(string $string)[]: string {
  return calc_sha_256($string);
}

/**
 * This code is heavily based on amosnier/sha-2.
 * @see https://github.com/amosnier/sha-2/tree/b29613850d6e54e7159197ef42c7d22d012b6367
 * That implementation is licensed under the `Unlicense` or `BSD-0` at your option.
 * Those licenses do not impose any requirements, including attribution.
 * I want to thank amosnier for writing it, so:
 *
 * ////////////////////////
 * // THANK YOU AMOSNIER //
 * ////////////////////////
 *
 * And now back to your regularly scheduled MIT licensed programming.
 */

// #region C standard and some C to Hack helpers

// C has arrays which are pointer to mutable memory.
// In order to create by-reference-semantics in Hack,
// I have modeled the C memory space as the member Sha_256['MEM'].
type memory_t = vec<uint8_t>;
// A memory which does not need to be taken by inout.
// The C code was const, so the memory is not altered.
type const_uint8_t_x = vec<uint8_t>;
// An address which is used to index into `MEM`.
type ptr_t = int;

type unsigned_int = int;
type uint8_t = int;
type size_t = int;
type uint32_t = int;
type uint64_t = int;

function cast_to_uint8_t(int $value)[]: int {
  return $value & 0xff;
}

function cast_to_uint32_t(int $value)[]: int {
  return $value & Math\UINT32_MAX;
}

function cast_string_to_memory_t(string $string)[]: memory_t {
  $out = vec[];

  $length = Str\length($string);
  for ($i = 0; $i < $length; ++$i) {
    $out[] = ord($string[$i]);
  }

  return $out;
}

function memcpy(
  inout memory_t $destination_memory,
  ptr_t $destination_ptr,
  const_uint8_t_x $source_memory,
  ptr_t $source_pointer,
  size_t $count,
)[]: void {
  for ($i = 0; $i < $count; ++$i) {
    $destination_memory[$destination_ptr + $i] =
      $source_memory[$source_pointer + $i];
  }
}

function memset(
  inout memory_t $memory,
  ptr_t $dest,
  uint8_t $ch,
  size_t $count,
)[]: void {
  for ($i = 0; $i < $count; ++$i) {
    $memory[$dest + $i] = $ch;
  }
}

// #endregion

const int TOTAL_LEN_LEN = 8;
const int SIZE_OF_SHA_256_CHUNK = 64;

type Sha_256 = shape(
  'chunk' => ptr_t,
  'chunk_pos' => ptr_t,
  'space_left' => size_t,
  'total_len' => uint64_t,
  'h' => vec<uint32_t>,
  'MEM' => vec<uint8_t>,
);

// hackfmt-ignore
const vec<int> K = vec[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
  0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
  0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
  0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
  0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2];

function right_rot(uint32_t $value, unsigned_int $count)[]: uint32_t {
  return $value >> $count | $value << (32 - $count);
}

function consume_chunk(
  inout vec<uint32_t> $h,
  ptr_t $ptr_p,
  const_uint8_t_x $p,
)[]: void {
  $ah = $h;
  $w = vec[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

  for ($i = 0; $i < 4; $i++) {
    for ($j = 0; $j < 16; $j++) {
      if ($i === 0) {
        $w[$j] = $p[$ptr_p + 0] << 24 |
          $p[$ptr_p + 1] << 16 |
          $p[$ptr_p + 2] << 8 |
          $p[$ptr_p + 3];
        $ptr_p += 4;
      } else {
        $s0 = right_rot($w[($j + 1) & 0xf], 7) ^
          right_rot($w[($j + 1) & 0xf], 18) ^
          ($w[($j + 1) & 0xf] >> 3);
        $s1 = right_rot($w[($j + 14) & 0xf], 17) ^
          right_rot($w[($j + 14) & 0xf], 19) ^
          ($w[($j + 14) & 0xf] >> 10);
        $w[$j] = cast_to_uint32_t($w[$j] + $s0 + $w[($j + 9) & 0xf] + $s1);
      }
      $s1 =
        right_rot($ah[4], 6) ^ right_rot($ah[4], 11) ^ right_rot($ah[4], 25);
      $ch = ($ah[4] & $ah[5]) ^ ~$ah[4] & $ah[6];

      $temp1 = $ah[7] + $s1 + $ch + K[$i << 4 | $j] + $w[$j];
      $s0 =
        right_rot($ah[0], 2) ^ right_rot($ah[0], 13) ^ right_rot($ah[0], 22);
      $maj = ($ah[0] & $ah[1]) ^ ($ah[0] & $ah[2]) ^ ($ah[1] & $ah[2]);
      $temp2 = $s0 + $maj;

      $ah[7] = $ah[6];
      $ah[6] = $ah[5];
      $ah[5] = $ah[4];
      $ah[4] = cast_to_uint32_t($ah[3] + $temp1);
      $ah[3] = $ah[2];
      $ah[2] = $ah[1];
      $ah[1] = $ah[0];
      $ah[0] = cast_to_uint32_t($temp1 + $temp2);
    }
  }

  for ($i = 0; $i < 8; $i++) {
    $h[$i] = cast_to_uint32_t($h[$i] + $ah[$i]);
  }
}

function sha_256_init()[]: Sha_256 {
  return shape(
    'chunk' => 0,
    'chunk_pos' => 0,
    'space_left' => SIZE_OF_SHA_256_CHUNK,
    'total_len' => 0,
    'h' => vec[
      0x6a09e667,
      0xbb67ae85,
      0x3c6ef372,
      0xa54ff53a,
      0x510e527f,
      0x9b05688c,
      0x1f83d9ab,
      0x5be0cd19,
    ],
    'MEM' => Vec\fill(SIZE_OF_SHA_256_CHUNK, 0),
  );
}

function sha_256_write(inout Sha_256 $sha_256, const_uint8_t_x $data)[]: void {
  $p = 0;
  $len = C\count($data);
  $sha_256['total_len'] += $len;

  while ($len > 0) {
    if (
      $sha_256['space_left'] === SIZE_OF_SHA_256_CHUNK &&
      $len >= SIZE_OF_SHA_256_CHUNK
    ) {
      consume_chunk(inout $sha_256['h'], $p, $data);
      $len -= SIZE_OF_SHA_256_CHUNK;
      $p += SIZE_OF_SHA_256_CHUNK;
      continue;
    }

    $consumed_len =
      $len < $sha_256['space_left'] ? $len : $sha_256['space_left'];
    memcpy(
      inout $sha_256['MEM'],
      $sha_256['chunk_pos'],
      $data,
      $p,
      $consumed_len,
    );
    $sha_256['space_left'] -= $consumed_len;
    $len -= $consumed_len;
    $p += $consumed_len;
    if ($sha_256['space_left'] === 0) {
      consume_chunk(inout $sha_256['h'], $sha_256['chunk'], $data);
      $sha_256['chunk_pos'] = $sha_256['chunk'];
      $sha_256['space_left'] = SIZE_OF_SHA_256_CHUNK;
    } else {
      $sha_256['chunk_pos'] += $consumed_len;
    }
  }
}

function sha_256_close(inout Sha_256 $sha_256)[]: string {
  $pos = $sha_256['chunk_pos'];
  $space_left = $sha_256['space_left'];

  $sha_256['MEM'][$pos] = 0x80;
  ++$pos;
  --$space_left;

  if ($space_left < TOTAL_LEN_LEN) {
    memset(inout $sha_256['MEM'], $pos, 0x00, $space_left);
    consume_chunk(inout $sha_256['h'], $sha_256['chunk'], $sha_256['MEM']);
    $pos = $sha_256['chunk'];
    $space_left = SIZE_OF_SHA_256_CHUNK;
  }

  $left = $space_left - TOTAL_LEN_LEN;
  memset(inout $sha_256['MEM'], $pos, 0x00, $left);
  $pos += $left;
  $len = $sha_256['total_len'];
  $sha_256['MEM'][$pos + 7] = cast_to_uint8_t($len << 3);
  $len >>= 5;
  for ($i = 6; $i >= 0; --$i) {
    $sha_256['MEM'][$pos + $i] = cast_to_uint8_t($len);
    $len >>= 8;
  }
  consume_chunk(inout $sha_256['h'], $sha_256['chunk'], $sha_256['MEM']);

  $hash = '';
  for ($i = 0; $i < 8; ++$i) {
    $hash .= chr($sha_256['h'][$i] >> 24);
    $hash .= chr($sha_256['h'][$i] >> 16);
    $hash .= chr($sha_256['h'][$i] >> 8);
    $hash .= chr($sha_256['h'][$i]);
  }

  return $hash;
}

function calc_sha_256(string $input)[]: string {
  $sha_256 = sha_256_init();
  sha_256_write(inout $sha_256, cast_string_to_memory_t($input));
  return sha_256_close(inout $sha_256);
}
