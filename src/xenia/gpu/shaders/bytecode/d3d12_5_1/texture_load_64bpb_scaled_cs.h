#if 0
//
// Generated by Microsoft (R) HLSL Shader Compiler 10.1
//
//
// Buffer Definitions: 
//
// cbuffer xe_texture_load_constants
// {
//
//   uint xe_texture_load_is_tiled_3d_endian_scale;// Offset:    0 Size:     4
//   uint xe_texture_load_guest_offset; // Offset:    4 Size:     4
//   uint xe_texture_load_guest_pitch_aligned;// Offset:    8 Size:     4
//   uint xe_texture_load_guest_z_stride_block_rows_aligned;// Offset:   12 Size:     4
//   uint3 xe_texture_load_size_blocks; // Offset:   16 Size:    12
//   uint xe_texture_load_host_offset;  // Offset:   28 Size:     4
//   uint xe_texture_load_host_pitch;   // Offset:   32 Size:     4
//   uint xe_texture_load_height_texels;// Offset:   36 Size:     4 [unused]
//
// }
//
//
// Resource Bindings:
//
// Name                                 Type  Format         Dim      ID      HLSL Bind  Count
// ------------------------------ ---------- ------- ----------- ------- -------------- ------
// xe_texture_load_source            texture   uint4         buf      T0             t0      1 
// xe_texture_load_dest                  UAV   uint4         buf      U0             u0      1 
// xe_texture_load_constants         cbuffer      NA          NA     CB0            cb0      1 
//
//
//
// Input signature:
//
// Name                 Index   Mask Register SysValue  Format   Used
// -------------------- ----- ------ -------- -------- ------- ------
// no Input
//
// Output signature:
//
// Name                 Index   Mask Register SysValue  Format   Used
// -------------------- ----- ------ -------- -------- ------- ------
// no Output
cs_5_1
dcl_globalFlags refactoringAllowed
dcl_constantbuffer CB0[0:0][3], immediateIndexed, space=0
dcl_resource_buffer (uint,uint,uint,uint) T0[0:0], space=0
dcl_uav_typed_buffer (uint,uint,uint,uint) U0[0:0], space=0
dcl_input vThreadID.xyz
dcl_temps 6
dcl_thread_group 4, 32, 1
ishl r0.x, vThreadID.x, l(2)
mov r0.y, vThreadID.y
uge r0.yz, r0.xxyx, CB0[0][1].xxyx
or r0.y, r0.z, r0.y
if_nz r0.y
  ret 
endif 
ishl r0.y, r0.x, l(3)
imad r0.z, vThreadID.z, CB0[0][1].y, vThreadID.y
imad r0.y, r0.z, CB0[0][2].x, r0.y
iadd r0.y, r0.y, CB0[0][1].w
and r0.z, CB0[0][0].x, l(2)
ubfe r1.xyz, l(2, 2, 2, 0), l(4, 6, 2, 0), CB0[0][0].xxxx
ushr r2.x, r0.x, l(1)
mov r2.y, vThreadID.y
udiv r0.xw, null, r2.xxxy, r1.xxxy
ishl r1.w, r0.x, l(1)
if_nz r0.z
  ishr r2.zw, r0.wwww, l(0, 0, 4, 3)
  ishr r0.z, vThreadID.z, l(2)
  ushr r3.xy, CB0[0][0].wzww, l(4, 5, 0, 0)
  imad r2.z, r0.z, r3.x, r2.z
  ibfe r3.xz, l(27, 0, 29, 0), l(4, 0, 2, 0), r0.xxxx
  imad r2.z, r2.z, r3.y, r3.x
  ishl r3.x, r0.w, l(11)
  and r3.x, r3.x, l(0x00003000)
  bfi r3.x, l(3), l(9), r1.w, r3.x
  ishr r3.x, r3.x, l(6)
  iadd r0.z, r0.z, r2.w
  bfi r2.w, l(1), l(1), r0.z, l(0)
  iadd r2.w, r2.w, r3.z
  bfi r2.w, l(2), l(1), r2.w, l(0)
  bfi r0.z, l(1), l(0), r0.z, r2.w
  bfi r2.zw, l(0, 0, 19, 19), l(0, 0, 11, 14), r2.zzzz, l(0, 0, 0, 0)
  imad r2.zw, r3.xxxx, l(0, 0, 2, 16), r2.zzzw
  bfi r2.zw, l(0, 0, 2, 2), l(0, 0, 9, 12), vThreadID.zzzz, r2.zzzw
  bfi r3.x, l(1), l(4), r0.w, l(0)
  ubfe r3.y, l(3), l(6), r2.z
  and r3.z, r0.z, l(6)
  bfi r0.z, l(1), l(8), r0.z, l(0)
  imad r0.z, r3.y, l(32), r0.z
  imad r0.z, r3.z, l(4), r0.z
  bfi r2.zw, l(0, 0, 5, 5), l(0, 0, 0, 3), r3.xxxx, r2.zzzw
  bfi r0.z, l(9), l(3), r0.z, r2.w
  bfi r0.z, l(6), l(0), r2.z, r0.z
else 
  ibfe r2.zw, l(0, 0, 27, 29), l(0, 0, 4, 2), r0.xxxx
  ishr r3.xy, r0.wwww, l(5, 2, 0, 0)
  ushr r3.z, CB0[0][0].z, l(5)
  imad r2.z, r3.x, r3.z, r2.z
  ishl r3.xz, r0.wwww, l(6, 0, 7, 0)
  and r3.xz, r3.xxzx, l(896, 0, 2048, 0)
  bfi r3.w, l(3), l(4), r1.w, r3.x
  bfi r3.w, l(22), l(10), r2.z, r3.w
  bfi r4.x, l(1), l(4), r0.w, l(0)
  iadd r3.w, r3.w, r4.x
  ishl r4.yz, r3.xxxx, l(0, 3, 2, 0)
  bfi r4.yz, l(0, 3, 3, 0), l(0, 7, 6, 0), r1.wwww, r4.yyzy
  bfi r4.yz, l(0, 22, 22, 0), l(0, 13, 12, 0), r2.zzzz, r4.yyzy
  imad r4.xy, r4.xxxx, l(8, 4, 0, 0), r4.yzyy
  bfi r1.w, l(12), l(0), r3.z, r4.x
  and r2.z, r4.y, l(1792)
  iadd r1.w, r1.w, r2.z
  and r2.z, r3.y, l(2)
  iadd r2.z, r2.w, r2.z
  bfi r2.z, l(2), l(6), r2.z, l(0)
  iadd r1.w, r1.w, r2.z
  bfi r0.z, l(6), l(0), r3.w, r1.w
endif 
imad r0.xw, -r0.xxxw, r1.xxxy, r2.xxxy
imul null, r1.w, r1.y, r1.x
imad r0.x, r0.x, r1.y, r0.w
ishl r0.x, r0.x, l(4)
imad r0.x, r0.z, r1.w, r0.x
iadd r0.x, r0.x, CB0[0][0].y
ushr r0.xy, r0.xyxx, l(4, 4, 0, 0)
ld r3.xyzw, r0.xxxx, T0[0].xyzw
ieq r2.yzw, r1.zzzz, l(0, 1, 2, 3)
or r0.zw, r2.zzzw, r2.yyyz
if_nz r0.z
  ishl r4.xyzw, r3.xyzw, l(8, 8, 8, 8)
  and r4.xyzw, r4.xyzw, l(0xff00ff00, 0xff00ff00, 0xff00ff00, 0xff00ff00)
  ushr r5.xyzw, r3.xyzw, l(8, 8, 8, 8)
  and r5.xyzw, r5.xyzw, l(0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff)
  iadd r3.xyzw, r4.xyzw, r5.xyzw
endif 
if_nz r0.w
  ushr r4.xyzw, r3.xyzw, l(16, 16, 16, 16)
  bfi r3.xyzw, l(16, 16, 16, 16), l(16, 16, 16, 16), r3.xyzw, r4.xyzw
endif 
store_uav_typed U0[0].xyzw, r0.yyyy, r3.xyzw
iadd r1.z, r0.y, l(1)
ult r1.w, l(1), r1.x
if_nz r1.w
  udiv r1.w, null, r2.x, r1.x
  imad r1.w, -r1.w, r1.x, r2.x
  iadd r2.x, r1.w, l(1)
  ieq r2.x, r1.x, r2.x
  if_nz r2.x
    ishl r1.x, r1.x, l(5)
    ishl r1.w, r1.w, l(4)
    iadd r1.x, -r1.w, r1.x
  else 
    mov r1.x, l(16)
  endif 
else 
  mov r1.x, l(32)
endif 
imul null, r1.x, r1.y, r1.x
ushr r1.x, r1.x, l(4)
iadd r0.x, r0.x, r1.x
ld r2.xyzw, r0.xxxx, T0[0].xyzw
if_nz r0.z
  ishl r3.xyzw, r2.xyzw, l(8, 8, 8, 8)
  and r3.xyzw, r3.xyzw, l(0xff00ff00, 0xff00ff00, 0xff00ff00, 0xff00ff00)
  ushr r4.xyzw, r2.xyzw, l(8, 8, 8, 8)
  and r4.xyzw, r4.xyzw, l(0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff)
  iadd r2.xyzw, r3.xyzw, r4.xyzw
endif 
if_nz r0.w
  ushr r3.xyzw, r2.xyzw, l(16, 16, 16, 16)
  bfi r2.xyzw, l(16, 16, 16, 16), l(16, 16, 16, 16), r2.xyzw, r3.xyzw
endif 
store_uav_typed U0[0].xyzw, r1.zzzz, r2.xyzw
ret 
// Approximately 125 instruction slots used
#endif

const BYTE texture_load_64bpb_scaled_cs[] =
{
     68,  88,  66,  67,  74,  59, 
    137, 121,  93,  62,  64,  66, 
     58, 206, 207,  85, 104, 121, 
    108,  88,   1,   0,   0,   0, 
     84,  21,   0,   0,   5,   0, 
      0,   0,  52,   0,   0,   0, 
     32,   4,   0,   0,  48,   4, 
      0,   0,  64,   4,   0,   0, 
    184,  20,   0,   0,  82,  68, 
     69,  70, 228,   3,   0,   0, 
      1,   0,   0,   0, 252,   0, 
      0,   0,   3,   0,   0,   0, 
     60,   0,   0,   0,   1,   5, 
     83,  67,   0,   5,   0,   0, 
    185,   3,   0,   0,  19,  19, 
     68,  37,  60,   0,   0,   0, 
     24,   0,   0,   0,  40,   0, 
      0,   0,  40,   0,   0,   0, 
     36,   0,   0,   0,  12,   0, 
      0,   0,   0,   0,   0,   0, 
    180,   0,   0,   0,   2,   0, 
      0,   0,   4,   0,   0,   0, 
      1,   0,   0,   0, 255, 255, 
    255, 255,   0,   0,   0,   0, 
      1,   0,   0,   0,  12,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0, 203,   0, 
      0,   0,   4,   0,   0,   0, 
      4,   0,   0,   0,   1,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0,   1,   0, 
      0,   0,  12,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0, 224,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   1,   0,   0,   0, 
      1,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
    120, 101,  95, 116, 101, 120, 
    116, 117, 114, 101,  95, 108, 
    111,  97, 100,  95, 115, 111, 
    117, 114,  99, 101,   0, 120, 
    101,  95, 116, 101, 120, 116, 
    117, 114, 101,  95, 108, 111, 
     97, 100,  95, 100, 101, 115, 
    116,   0, 120, 101,  95, 116, 
    101, 120, 116, 117, 114, 101, 
     95, 108, 111,  97, 100,  95, 
     99, 111, 110, 115, 116,  97, 
    110, 116, 115,   0, 171, 171, 
    224,   0,   0,   0,   8,   0, 
      0,   0,  20,   1,   0,   0, 
     48,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
     84,   2,   0,   0,   0,   0, 
      0,   0,   4,   0,   0,   0, 
      2,   0,   0,   0, 132,   2, 
      0,   0,   0,   0,   0,   0, 
    255, 255, 255, 255,   0,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0, 168,   2, 
      0,   0,   4,   0,   0,   0, 
      4,   0,   0,   0,   2,   0, 
      0,   0, 132,   2,   0,   0, 
      0,   0,   0,   0, 255, 255, 
    255, 255,   0,   0,   0,   0, 
    255, 255, 255, 255,   0,   0, 
      0,   0, 197,   2,   0,   0, 
      8,   0,   0,   0,   4,   0, 
      0,   0,   2,   0,   0,   0, 
    132,   2,   0,   0,   0,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0, 255, 255, 
    255, 255,   0,   0,   0,   0, 
    233,   2,   0,   0,  12,   0, 
      0,   0,   4,   0,   0,   0, 
      2,   0,   0,   0, 132,   2, 
      0,   0,   0,   0,   0,   0, 
    255, 255, 255, 255,   0,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0,  27,   3, 
      0,   0,  16,   0,   0,   0, 
     12,   0,   0,   0,   2,   0, 
      0,   0,  64,   3,   0,   0, 
      0,   0,   0,   0, 255, 255, 
    255, 255,   0,   0,   0,   0, 
    255, 255, 255, 255,   0,   0, 
      0,   0, 100,   3,   0,   0, 
     28,   0,   0,   0,   4,   0, 
      0,   0,   2,   0,   0,   0, 
    132,   2,   0,   0,   0,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0, 255, 255, 
    255, 255,   0,   0,   0,   0, 
    128,   3,   0,   0,  32,   0, 
      0,   0,   4,   0,   0,   0, 
      2,   0,   0,   0, 132,   2, 
      0,   0,   0,   0,   0,   0, 
    255, 255, 255, 255,   0,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0, 155,   3, 
      0,   0,  36,   0,   0,   0, 
      4,   0,   0,   0,   0,   0, 
      0,   0, 132,   2,   0,   0, 
      0,   0,   0,   0, 255, 255, 
    255, 255,   0,   0,   0,   0, 
    255, 255, 255, 255,   0,   0, 
      0,   0, 120, 101,  95, 116, 
    101, 120, 116, 117, 114, 101, 
     95, 108, 111,  97, 100,  95, 
    105, 115,  95, 116, 105, 108, 
    101, 100,  95,  51, 100,  95, 
    101, 110, 100, 105,  97, 110, 
     95, 115,  99,  97, 108, 101, 
      0, 100, 119, 111, 114, 100, 
      0, 171,   0,   0,  19,   0, 
      1,   0,   1,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0, 125,   2, 
      0,   0, 120, 101,  95, 116, 
    101, 120, 116, 117, 114, 101, 
     95, 108, 111,  97, 100,  95, 
    103, 117, 101, 115, 116,  95, 
    111, 102, 102, 115, 101, 116, 
      0, 120, 101,  95, 116, 101, 
    120, 116, 117, 114, 101,  95, 
    108, 111,  97, 100,  95, 103, 
    117, 101, 115, 116,  95, 112, 
    105, 116,  99, 104,  95,  97, 
    108, 105, 103, 110, 101, 100, 
      0, 120, 101,  95, 116, 101, 
    120, 116, 117, 114, 101,  95, 
    108, 111,  97, 100,  95, 103, 
    117, 101, 115, 116,  95, 122, 
     95, 115, 116, 114, 105, 100, 
    101,  95,  98, 108, 111,  99, 
    107,  95, 114, 111, 119, 115, 
     95,  97, 108, 105, 103, 110, 
    101, 100,   0, 120, 101,  95, 
    116, 101, 120, 116, 117, 114, 
    101,  95, 108, 111,  97, 100, 
     95, 115, 105, 122, 101,  95, 
     98, 108, 111,  99, 107, 115, 
      0, 117, 105, 110, 116,  51, 
      0, 171, 171, 171,   1,   0, 
     19,   0,   1,   0,   3,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
     55,   3,   0,   0, 120, 101, 
     95, 116, 101, 120, 116, 117, 
    114, 101,  95, 108, 111,  97, 
    100,  95, 104, 111, 115, 116, 
     95, 111, 102, 102, 115, 101, 
    116,   0, 120, 101,  95, 116, 
    101, 120, 116, 117, 114, 101, 
     95, 108, 111,  97, 100,  95, 
    104, 111, 115, 116,  95, 112, 
    105, 116,  99, 104,   0, 120, 
    101,  95, 116, 101, 120, 116, 
    117, 114, 101,  95, 108, 111, 
     97, 100,  95, 104, 101, 105, 
    103, 104, 116,  95, 116, 101, 
    120, 101, 108, 115,   0,  77, 
    105,  99, 114, 111, 115, 111, 
    102, 116,  32,  40,  82,  41, 
     32,  72,  76,  83,  76,  32, 
     83, 104,  97, 100, 101, 114, 
     32,  67, 111, 109, 112, 105, 
    108, 101, 114,  32,  49,  48, 
     46,  49,   0, 171, 171, 171, 
     73,  83,  71,  78,   8,   0, 
      0,   0,   0,   0,   0,   0, 
      8,   0,   0,   0,  79,  83, 
     71,  78,   8,   0,   0,   0, 
      0,   0,   0,   0,   8,   0, 
      0,   0,  83,  72,  69,  88, 
    112,  16,   0,   0,  81,   0, 
      5,   0,  28,   4,   0,   0, 
    106,   8,   0,   1,  89,   0, 
      0,   7,  70, 142,  48,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      3,   0,   0,   0,   0,   0, 
      0,   0,  88,   8,   0,   7, 
     70, 126,  48,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,  68,  68, 
      0,   0,   0,   0,   0,   0, 
    156,   8,   0,   7,  70, 238, 
     49,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,  68,  68,   0,   0, 
      0,   0,   0,   0,  95,   0, 
      0,   2, 114,   0,   2,   0, 
    104,   0,   0,   2,   6,   0, 
      0,   0, 155,   0,   0,   4, 
      4,   0,   0,   0,  32,   0, 
      0,   0,   1,   0,   0,   0, 
     41,   0,   0,   6,  18,   0, 
     16,   0,   0,   0,   0,   0, 
     10,   0,   2,   0,   1,  64, 
      0,   0,   2,   0,   0,   0, 
     54,   0,   0,   4,  34,   0, 
     16,   0,   0,   0,   0,   0, 
     26,   0,   2,   0,  80,   0, 
      0,   9,  98,   0,  16,   0, 
      0,   0,   0,   0,   6,   1, 
     16,   0,   0,   0,   0,   0, 
      6, 129,  48,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,  60,   0, 
      0,   7,  34,   0,  16,   0, 
      0,   0,   0,   0,  42,   0, 
     16,   0,   0,   0,   0,   0, 
     26,   0,  16,   0,   0,   0, 
      0,   0,  31,   0,   4,   3, 
     26,   0,  16,   0,   0,   0, 
      0,   0,  62,   0,   0,   1, 
     21,   0,   0,   1,  41,   0, 
      0,   7,  34,   0,  16,   0, 
      0,   0,   0,   0,  10,   0, 
     16,   0,   0,   0,   0,   0, 
      1,  64,   0,   0,   3,   0, 
      0,   0,  35,   0,   0,   9, 
     66,   0,  16,   0,   0,   0, 
      0,   0,  42,   0,   2,   0, 
     26, 128,  48,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,  26,   0, 
      2,   0,  35,   0,   0,  11, 
     34,   0,  16,   0,   0,   0, 
      0,   0,  42,   0,  16,   0, 
      0,   0,   0,   0,  10, 128, 
     48,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   2,   0, 
      0,   0,  26,   0,  16,   0, 
      0,   0,   0,   0,  30,   0, 
      0,   9,  34,   0,  16,   0, 
      0,   0,   0,   0,  26,   0, 
     16,   0,   0,   0,   0,   0, 
     58, 128,  48,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,   1,   0, 
      0,   9,  66,   0,  16,   0, 
      0,   0,   0,   0,  10, 128, 
     48,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   1,  64,   0,   0, 
      2,   0,   0,   0, 138,   0, 
      0,  17, 114,   0,  16,   0, 
      1,   0,   0,   0,   2,  64, 
      0,   0,   2,   0,   0,   0, 
      2,   0,   0,   0,   2,   0, 
      0,   0,   0,   0,   0,   0, 
      2,  64,   0,   0,   4,   0, 
      0,   0,   6,   0,   0,   0, 
      2,   0,   0,   0,   0,   0, 
      0,   0,   6, 128,  48,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
     85,   0,   0,   7,  18,   0, 
     16,   0,   2,   0,   0,   0, 
     10,   0,  16,   0,   0,   0, 
      0,   0,   1,  64,   0,   0, 
      1,   0,   0,   0,  54,   0, 
      0,   4,  34,   0,  16,   0, 
      2,   0,   0,   0,  26,   0, 
      2,   0,  78,   0,   0,   8, 
    146,   0,  16,   0,   0,   0, 
      0,   0,   0, 208,   0,   0, 
      6,   4,  16,   0,   2,   0, 
      0,   0,   6,   4,  16,   0, 
      1,   0,   0,   0,  41,   0, 
      0,   7, 130,   0,  16,   0, 
      1,   0,   0,   0,  10,   0, 
     16,   0,   0,   0,   0,   0, 
      1,  64,   0,   0,   1,   0, 
      0,   0,  31,   0,   4,   3, 
     42,   0,  16,   0,   0,   0, 
      0,   0,  42,   0,   0,  10, 
    194,   0,  16,   0,   2,   0, 
      0,   0, 246,  15,  16,   0, 
      0,   0,   0,   0,   2,  64, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   4,   0, 
      0,   0,   3,   0,   0,   0, 
     42,   0,   0,   6,  66,   0, 
     16,   0,   0,   0,   0,   0, 
     42,   0,   2,   0,   1,  64, 
      0,   0,   2,   0,   0,   0, 
     85,   0,   0,  12,  50,   0, 
     16,   0,   3,   0,   0,   0, 
    182, 143,  48,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   2,  64, 
      0,   0,   4,   0,   0,   0, 
      5,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
     35,   0,   0,   9,  66,   0, 
     16,   0,   2,   0,   0,   0, 
     42,   0,  16,   0,   0,   0, 
      0,   0,  10,   0,  16,   0, 
      3,   0,   0,   0,  42,   0, 
     16,   0,   2,   0,   0,   0, 
    139,   0,   0,  15,  82,   0, 
     16,   0,   3,   0,   0,   0, 
      2,  64,   0,   0,  27,   0, 
      0,   0,   0,   0,   0,   0, 
     29,   0,   0,   0,   0,   0, 
      0,   0,   2,  64,   0,   0, 
      4,   0,   0,   0,   0,   0, 
      0,   0,   2,   0,   0,   0, 
      0,   0,   0,   0,   6,   0, 
     16,   0,   0,   0,   0,   0, 
     35,   0,   0,   9,  66,   0, 
     16,   0,   2,   0,   0,   0, 
     42,   0,  16,   0,   2,   0, 
      0,   0,  26,   0,  16,   0, 
      3,   0,   0,   0,  10,   0, 
     16,   0,   3,   0,   0,   0, 
     41,   0,   0,   7,  18,   0, 
     16,   0,   3,   0,   0,   0, 
     58,   0,  16,   0,   0,   0, 
      0,   0,   1,  64,   0,   0, 
     11,   0,   0,   0,   1,   0, 
      0,   7,  18,   0,  16,   0, 
      3,   0,   0,   0,  10,   0, 
     16,   0,   3,   0,   0,   0, 
      1,  64,   0,   0,   0,  48, 
      0,   0, 140,   0,   0,  11, 
     18,   0,  16,   0,   3,   0, 
      0,   0,   1,  64,   0,   0, 
      3,   0,   0,   0,   1,  64, 
      0,   0,   9,   0,   0,   0, 
     58,   0,  16,   0,   1,   0, 
      0,   0,  10,   0,  16,   0, 
      3,   0,   0,   0,  42,   0, 
      0,   7,  18,   0,  16,   0, 
      3,   0,   0,   0,  10,   0, 
     16,   0,   3,   0,   0,   0, 
      1,  64,   0,   0,   6,   0, 
      0,   0,  30,   0,   0,   7, 
     66,   0,  16,   0,   0,   0, 
      0,   0,  42,   0,  16,   0, 
      0,   0,   0,   0,  58,   0, 
     16,   0,   2,   0,   0,   0, 
    140,   0,   0,  11, 130,   0, 
     16,   0,   2,   0,   0,   0, 
      1,  64,   0,   0,   1,   0, 
      0,   0,   1,  64,   0,   0, 
      1,   0,   0,   0,  42,   0, 
     16,   0,   0,   0,   0,   0, 
      1,  64,   0,   0,   0,   0, 
      0,   0,  30,   0,   0,   7, 
    130,   0,  16,   0,   2,   0, 
      0,   0,  58,   0,  16,   0, 
      2,   0,   0,   0,  42,   0, 
     16,   0,   3,   0,   0,   0, 
    140,   0,   0,  11, 130,   0, 
     16,   0,   2,   0,   0,   0, 
      1,  64,   0,   0,   2,   0, 
      0,   0,   1,  64,   0,   0, 
      1,   0,   0,   0,  58,   0, 
     16,   0,   2,   0,   0,   0, 
      1,  64,   0,   0,   0,   0, 
      0,   0, 140,   0,   0,  11, 
     66,   0,  16,   0,   0,   0, 
      0,   0,   1,  64,   0,   0, 
      1,   0,   0,   0,   1,  64, 
      0,   0,   0,   0,   0,   0, 
     42,   0,  16,   0,   0,   0, 
      0,   0,  58,   0,  16,   0, 
      2,   0,   0,   0, 140,   0, 
      0,  20, 194,   0,  16,   0, 
      2,   0,   0,   0,   2,  64, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,  19,   0, 
      0,   0,  19,   0,   0,   0, 
      2,  64,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
     11,   0,   0,   0,  14,   0, 
      0,   0, 166,  10,  16,   0, 
      2,   0,   0,   0,   2,  64, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
     35,   0,   0,  12, 194,   0, 
     16,   0,   2,   0,   0,   0, 
      6,   0,  16,   0,   3,   0, 
      0,   0,   2,  64,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   2,   0,   0,   0, 
     16,   0,   0,   0, 166,  14, 
     16,   0,   2,   0,   0,   0, 
    140,   0,   0,  16, 194,   0, 
     16,   0,   2,   0,   0,   0, 
      2,  64,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      2,   0,   0,   0,   2,   0, 
      0,   0,   2,  64,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   9,   0,   0,   0, 
     12,   0,   0,   0, 166,  10, 
      2,   0, 166,  14,  16,   0, 
      2,   0,   0,   0, 140,   0, 
      0,  11,  18,   0,  16,   0, 
      3,   0,   0,   0,   1,  64, 
      0,   0,   1,   0,   0,   0, 
      1,  64,   0,   0,   4,   0, 
      0,   0,  58,   0,  16,   0, 
      0,   0,   0,   0,   1,  64, 
      0,   0,   0,   0,   0,   0, 
    138,   0,   0,   9,  34,   0, 
     16,   0,   3,   0,   0,   0, 
      1,  64,   0,   0,   3,   0, 
      0,   0,   1,  64,   0,   0, 
      6,   0,   0,   0,  42,   0, 
     16,   0,   2,   0,   0,   0, 
      1,   0,   0,   7,  66,   0, 
     16,   0,   3,   0,   0,   0, 
     42,   0,  16,   0,   0,   0, 
      0,   0,   1,  64,   0,   0, 
      6,   0,   0,   0, 140,   0, 
      0,  11,  66,   0,  16,   0, 
      0,   0,   0,   0,   1,  64, 
      0,   0,   1,   0,   0,   0, 
      1,  64,   0,   0,   8,   0, 
      0,   0,  42,   0,  16,   0, 
      0,   0,   0,   0,   1,  64, 
      0,   0,   0,   0,   0,   0, 
     35,   0,   0,   9,  66,   0, 
     16,   0,   0,   0,   0,   0, 
     26,   0,  16,   0,   3,   0, 
      0,   0,   1,  64,   0,   0, 
     32,   0,   0,   0,  42,   0, 
     16,   0,   0,   0,   0,   0, 
     35,   0,   0,   9,  66,   0, 
     16,   0,   0,   0,   0,   0, 
     42,   0,  16,   0,   3,   0, 
      0,   0,   1,  64,   0,   0, 
      4,   0,   0,   0,  42,   0, 
     16,   0,   0,   0,   0,   0, 
    140,   0,   0,  17, 194,   0, 
     16,   0,   2,   0,   0,   0, 
      2,  64,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      5,   0,   0,   0,   5,   0, 
      0,   0,   2,  64,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      3,   0,   0,   0,   6,   0, 
     16,   0,   3,   0,   0,   0, 
    166,  14,  16,   0,   2,   0, 
      0,   0, 140,   0,   0,  11, 
     66,   0,  16,   0,   0,   0, 
      0,   0,   1,  64,   0,   0, 
      9,   0,   0,   0,   1,  64, 
      0,   0,   3,   0,   0,   0, 
     42,   0,  16,   0,   0,   0, 
      0,   0,  58,   0,  16,   0, 
      2,   0,   0,   0, 140,   0, 
      0,  11,  66,   0,  16,   0, 
      0,   0,   0,   0,   1,  64, 
      0,   0,   6,   0,   0,   0, 
      1,  64,   0,   0,   0,   0, 
      0,   0,  42,   0,  16,   0, 
      2,   0,   0,   0,  42,   0, 
     16,   0,   0,   0,   0,   0, 
     18,   0,   0,   1, 139,   0, 
      0,  15, 194,   0,  16,   0, 
      2,   0,   0,   0,   2,  64, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,  27,   0, 
      0,   0,  29,   0,   0,   0, 
      2,  64,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      4,   0,   0,   0,   2,   0, 
      0,   0,   6,   0,  16,   0, 
      0,   0,   0,   0,  42,   0, 
      0,  10,  50,   0,  16,   0, 
      3,   0,   0,   0, 246,  15, 
     16,   0,   0,   0,   0,   0, 
      2,  64,   0,   0,   5,   0, 
      0,   0,   2,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,  85,   0,   0,   9, 
     66,   0,  16,   0,   3,   0, 
      0,   0,  42, 128,  48,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      1,  64,   0,   0,   5,   0, 
      0,   0,  35,   0,   0,   9, 
     66,   0,  16,   0,   2,   0, 
      0,   0,  10,   0,  16,   0, 
      3,   0,   0,   0,  42,   0, 
     16,   0,   3,   0,   0,   0, 
     42,   0,  16,   0,   2,   0, 
      0,   0,  41,   0,   0,  10, 
     82,   0,  16,   0,   3,   0, 
      0,   0, 246,  15,  16,   0, 
      0,   0,   0,   0,   2,  64, 
      0,   0,   6,   0,   0,   0, 
      0,   0,   0,   0,   7,   0, 
      0,   0,   0,   0,   0,   0, 
      1,   0,   0,  10,  82,   0, 
     16,   0,   3,   0,   0,   0, 
      6,   2,  16,   0,   3,   0, 
      0,   0,   2,  64,   0,   0, 
    128,   3,   0,   0,   0,   0, 
      0,   0,   0,   8,   0,   0, 
      0,   0,   0,   0, 140,   0, 
      0,  11, 130,   0,  16,   0, 
      3,   0,   0,   0,   1,  64, 
      0,   0,   3,   0,   0,   0, 
      1,  64,   0,   0,   4,   0, 
      0,   0,  58,   0,  16,   0, 
      1,   0,   0,   0,  10,   0, 
     16,   0,   3,   0,   0,   0, 
    140,   0,   0,  11, 130,   0, 
     16,   0,   3,   0,   0,   0, 
      1,  64,   0,   0,  22,   0, 
      0,   0,   1,  64,   0,   0, 
     10,   0,   0,   0,  42,   0, 
     16,   0,   2,   0,   0,   0, 
     58,   0,  16,   0,   3,   0, 
      0,   0, 140,   0,   0,  11, 
     18,   0,  16,   0,   4,   0, 
      0,   0,   1,  64,   0,   0, 
      1,   0,   0,   0,   1,  64, 
      0,   0,   4,   0,   0,   0, 
     58,   0,  16,   0,   0,   0, 
      0,   0,   1,  64,   0,   0, 
      0,   0,   0,   0,  30,   0, 
      0,   7, 130,   0,  16,   0, 
      3,   0,   0,   0,  58,   0, 
     16,   0,   3,   0,   0,   0, 
     10,   0,  16,   0,   4,   0, 
      0,   0,  41,   0,   0,  10, 
     98,   0,  16,   0,   4,   0, 
      0,   0,   6,   0,  16,   0, 
      3,   0,   0,   0,   2,  64, 
      0,   0,   0,   0,   0,   0, 
      3,   0,   0,   0,   2,   0, 
      0,   0,   0,   0,   0,   0, 
    140,   0,   0,  17,  98,   0, 
     16,   0,   4,   0,   0,   0, 
      2,  64,   0,   0,   0,   0, 
      0,   0,   3,   0,   0,   0, 
      3,   0,   0,   0,   0,   0, 
      0,   0,   2,  64,   0,   0, 
      0,   0,   0,   0,   7,   0, 
      0,   0,   6,   0,   0,   0, 
      0,   0,   0,   0, 246,  15, 
     16,   0,   1,   0,   0,   0, 
     86,   6,  16,   0,   4,   0, 
      0,   0, 140,   0,   0,  17, 
     98,   0,  16,   0,   4,   0, 
      0,   0,   2,  64,   0,   0, 
      0,   0,   0,   0,  22,   0, 
      0,   0,  22,   0,   0,   0, 
      0,   0,   0,   0,   2,  64, 
      0,   0,   0,   0,   0,   0, 
     13,   0,   0,   0,  12,   0, 
      0,   0,   0,   0,   0,   0, 
    166,  10,  16,   0,   2,   0, 
      0,   0,  86,   6,  16,   0, 
      4,   0,   0,   0,  35,   0, 
      0,  12,  50,   0,  16,   0, 
      4,   0,   0,   0,   6,   0, 
     16,   0,   4,   0,   0,   0, 
      2,  64,   0,   0,   8,   0, 
      0,   0,   4,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0, 150,   5,  16,   0, 
      4,   0,   0,   0, 140,   0, 
      0,  11, 130,   0,  16,   0, 
      1,   0,   0,   0,   1,  64, 
      0,   0,  12,   0,   0,   0, 
      1,  64,   0,   0,   0,   0, 
      0,   0,  42,   0,  16,   0, 
      3,   0,   0,   0,  10,   0, 
     16,   0,   4,   0,   0,   0, 
      1,   0,   0,   7,  66,   0, 
     16,   0,   2,   0,   0,   0, 
     26,   0,  16,   0,   4,   0, 
      0,   0,   1,  64,   0,   0, 
      0,   7,   0,   0,  30,   0, 
      0,   7, 130,   0,  16,   0, 
      1,   0,   0,   0,  58,   0, 
     16,   0,   1,   0,   0,   0, 
     42,   0,  16,   0,   2,   0, 
      0,   0,   1,   0,   0,   7, 
     66,   0,  16,   0,   2,   0, 
      0,   0,  26,   0,  16,   0, 
      3,   0,   0,   0,   1,  64, 
      0,   0,   2,   0,   0,   0, 
     30,   0,   0,   7,  66,   0, 
     16,   0,   2,   0,   0,   0, 
     58,   0,  16,   0,   2,   0, 
      0,   0,  42,   0,  16,   0, 
      2,   0,   0,   0, 140,   0, 
      0,  11,  66,   0,  16,   0, 
      2,   0,   0,   0,   1,  64, 
      0,   0,   2,   0,   0,   0, 
      1,  64,   0,   0,   6,   0, 
      0,   0,  42,   0,  16,   0, 
      2,   0,   0,   0,   1,  64, 
      0,   0,   0,   0,   0,   0, 
     30,   0,   0,   7, 130,   0, 
     16,   0,   1,   0,   0,   0, 
     58,   0,  16,   0,   1,   0, 
      0,   0,  42,   0,  16,   0, 
      2,   0,   0,   0, 140,   0, 
      0,  11,  66,   0,  16,   0, 
      0,   0,   0,   0,   1,  64, 
      0,   0,   6,   0,   0,   0, 
      1,  64,   0,   0,   0,   0, 
      0,   0,  58,   0,  16,   0, 
      3,   0,   0,   0,  58,   0, 
     16,   0,   1,   0,   0,   0, 
     21,   0,   0,   1,  35,   0, 
      0,  10, 146,   0,  16,   0, 
      0,   0,   0,   0,   6,  12, 
     16, 128,  65,   0,   0,   0, 
      0,   0,   0,   0,   6,   4, 
     16,   0,   1,   0,   0,   0, 
      6,   4,  16,   0,   2,   0, 
      0,   0,  38,   0,   0,   8, 
      0, 208,   0,   0, 130,   0, 
     16,   0,   1,   0,   0,   0, 
     26,   0,  16,   0,   1,   0, 
      0,   0,  10,   0,  16,   0, 
      1,   0,   0,   0,  35,   0, 
      0,   9,  18,   0,  16,   0, 
      0,   0,   0,   0,  10,   0, 
     16,   0,   0,   0,   0,   0, 
     26,   0,  16,   0,   1,   0, 
      0,   0,  58,   0,  16,   0, 
      0,   0,   0,   0,  41,   0, 
      0,   7,  18,   0,  16,   0, 
      0,   0,   0,   0,  10,   0, 
     16,   0,   0,   0,   0,   0, 
      1,  64,   0,   0,   4,   0, 
      0,   0,  35,   0,   0,   9, 
     18,   0,  16,   0,   0,   0, 
      0,   0,  42,   0,  16,   0, 
      0,   0,   0,   0,  58,   0, 
     16,   0,   1,   0,   0,   0, 
     10,   0,  16,   0,   0,   0, 
      0,   0,  30,   0,   0,   9, 
     18,   0,  16,   0,   0,   0, 
      0,   0,  10,   0,  16,   0, 
      0,   0,   0,   0,  26, 128, 
     48,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,  85,   0,   0,  10, 
     50,   0,  16,   0,   0,   0, 
      0,   0,  70,   0,  16,   0, 
      0,   0,   0,   0,   2,  64, 
      0,   0,   4,   0,   0,   0, 
      4,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
     45,   0,   0,   8, 242,   0, 
     16,   0,   3,   0,   0,   0, 
      6,   0,  16,   0,   0,   0, 
      0,   0,  70, 126,  32,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,  32,   0,   0,  10, 
    226,   0,  16,   0,   2,   0, 
      0,   0, 166,  10,  16,   0, 
      1,   0,   0,   0,   2,  64, 
      0,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,   2,   0, 
      0,   0,   3,   0,   0,   0, 
     60,   0,   0,   7, 194,   0, 
     16,   0,   0,   0,   0,   0, 
    166,  14,  16,   0,   2,   0, 
      0,   0,  86,   9,  16,   0, 
      2,   0,   0,   0,  31,   0, 
      4,   3,  42,   0,  16,   0, 
      0,   0,   0,   0,  41,   0, 
      0,  10, 242,   0,  16,   0, 
      4,   0,   0,   0,  70,  14, 
     16,   0,   3,   0,   0,   0, 
      2,  64,   0,   0,   8,   0, 
      0,   0,   8,   0,   0,   0, 
      8,   0,   0,   0,   8,   0, 
      0,   0,   1,   0,   0,  10, 
    242,   0,  16,   0,   4,   0, 
      0,   0,  70,  14,  16,   0, 
      4,   0,   0,   0,   2,  64, 
      0,   0,   0, 255,   0, 255, 
      0, 255,   0, 255,   0, 255, 
      0, 255,   0, 255,   0, 255, 
     85,   0,   0,  10, 242,   0, 
     16,   0,   5,   0,   0,   0, 
     70,  14,  16,   0,   3,   0, 
      0,   0,   2,  64,   0,   0, 
      8,   0,   0,   0,   8,   0, 
      0,   0,   8,   0,   0,   0, 
      8,   0,   0,   0,   1,   0, 
      0,  10, 242,   0,  16,   0, 
      5,   0,   0,   0,  70,  14, 
     16,   0,   5,   0,   0,   0, 
      2,  64,   0,   0, 255,   0, 
    255,   0, 255,   0, 255,   0, 
    255,   0, 255,   0, 255,   0, 
    255,   0,  30,   0,   0,   7, 
    242,   0,  16,   0,   3,   0, 
      0,   0,  70,  14,  16,   0, 
      4,   0,   0,   0,  70,  14, 
     16,   0,   5,   0,   0,   0, 
     21,   0,   0,   1,  31,   0, 
      4,   3,  58,   0,  16,   0, 
      0,   0,   0,   0,  85,   0, 
      0,  10, 242,   0,  16,   0, 
      4,   0,   0,   0,  70,  14, 
     16,   0,   3,   0,   0,   0, 
      2,  64,   0,   0,  16,   0, 
      0,   0,  16,   0,   0,   0, 
     16,   0,   0,   0,  16,   0, 
      0,   0, 140,   0,   0,  17, 
    242,   0,  16,   0,   3,   0, 
      0,   0,   2,  64,   0,   0, 
     16,   0,   0,   0,  16,   0, 
      0,   0,  16,   0,   0,   0, 
     16,   0,   0,   0,   2,  64, 
      0,   0,  16,   0,   0,   0, 
     16,   0,   0,   0,  16,   0, 
      0,   0,  16,   0,   0,   0, 
     70,  14,  16,   0,   3,   0, 
      0,   0,  70,  14,  16,   0, 
      4,   0,   0,   0,  21,   0, 
      0,   1, 164,   0,   0,   8, 
    242, 224,  33,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
     86,   5,  16,   0,   0,   0, 
      0,   0,  70,  14,  16,   0, 
      3,   0,   0,   0,  30,   0, 
      0,   7,  66,   0,  16,   0, 
      1,   0,   0,   0,  26,   0, 
     16,   0,   0,   0,   0,   0, 
      1,  64,   0,   0,   1,   0, 
      0,   0,  79,   0,   0,   7, 
    130,   0,  16,   0,   1,   0, 
      0,   0,   1,  64,   0,   0, 
      1,   0,   0,   0,  10,   0, 
     16,   0,   1,   0,   0,   0, 
     31,   0,   4,   3,  58,   0, 
     16,   0,   1,   0,   0,   0, 
     78,   0,   0,   8, 130,   0, 
     16,   0,   1,   0,   0,   0, 
      0, 208,   0,   0,  10,   0, 
     16,   0,   2,   0,   0,   0, 
     10,   0,  16,   0,   1,   0, 
      0,   0,  35,   0,   0,  10, 
    130,   0,  16,   0,   1,   0, 
      0,   0,  58,   0,  16, 128, 
     65,   0,   0,   0,   1,   0, 
      0,   0,  10,   0,  16,   0, 
      1,   0,   0,   0,  10,   0, 
     16,   0,   2,   0,   0,   0, 
     30,   0,   0,   7,  18,   0, 
     16,   0,   2,   0,   0,   0, 
     58,   0,  16,   0,   1,   0, 
      0,   0,   1,  64,   0,   0, 
      1,   0,   0,   0,  32,   0, 
      0,   7,  18,   0,  16,   0, 
      2,   0,   0,   0,  10,   0, 
     16,   0,   1,   0,   0,   0, 
     10,   0,  16,   0,   2,   0, 
      0,   0,  31,   0,   4,   3, 
     10,   0,  16,   0,   2,   0, 
      0,   0,  41,   0,   0,   7, 
     18,   0,  16,   0,   1,   0, 
      0,   0,  10,   0,  16,   0, 
      1,   0,   0,   0,   1,  64, 
      0,   0,   5,   0,   0,   0, 
     41,   0,   0,   7, 130,   0, 
     16,   0,   1,   0,   0,   0, 
     58,   0,  16,   0,   1,   0, 
      0,   0,   1,  64,   0,   0, 
      4,   0,   0,   0,  30,   0, 
      0,   8,  18,   0,  16,   0, 
      1,   0,   0,   0,  58,   0, 
     16, 128,  65,   0,   0,   0, 
      1,   0,   0,   0,  10,   0, 
     16,   0,   1,   0,   0,   0, 
     18,   0,   0,   1,  54,   0, 
      0,   5,  18,   0,  16,   0, 
      1,   0,   0,   0,   1,  64, 
      0,   0,  16,   0,   0,   0, 
     21,   0,   0,   1,  18,   0, 
      0,   1,  54,   0,   0,   5, 
     18,   0,  16,   0,   1,   0, 
      0,   0,   1,  64,   0,   0, 
     32,   0,   0,   0,  21,   0, 
      0,   1,  38,   0,   0,   8, 
      0, 208,   0,   0,  18,   0, 
     16,   0,   1,   0,   0,   0, 
     26,   0,  16,   0,   1,   0, 
      0,   0,  10,   0,  16,   0, 
      1,   0,   0,   0,  85,   0, 
      0,   7,  18,   0,  16,   0, 
      1,   0,   0,   0,  10,   0, 
     16,   0,   1,   0,   0,   0, 
      1,  64,   0,   0,   4,   0, 
      0,   0,  30,   0,   0,   7, 
     18,   0,  16,   0,   0,   0, 
      0,   0,  10,   0,  16,   0, 
      0,   0,   0,   0,  10,   0, 
     16,   0,   1,   0,   0,   0, 
     45,   0,   0,   8, 242,   0, 
     16,   0,   2,   0,   0,   0, 
      6,   0,  16,   0,   0,   0, 
      0,   0,  70, 126,  32,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,  31,   0,   4,   3, 
     42,   0,  16,   0,   0,   0, 
      0,   0,  41,   0,   0,  10, 
    242,   0,  16,   0,   3,   0, 
      0,   0,  70,  14,  16,   0, 
      2,   0,   0,   0,   2,  64, 
      0,   0,   8,   0,   0,   0, 
      8,   0,   0,   0,   8,   0, 
      0,   0,   8,   0,   0,   0, 
      1,   0,   0,  10, 242,   0, 
     16,   0,   3,   0,   0,   0, 
     70,  14,  16,   0,   3,   0, 
      0,   0,   2,  64,   0,   0, 
      0, 255,   0, 255,   0, 255, 
      0, 255,   0, 255,   0, 255, 
      0, 255,   0, 255,  85,   0, 
      0,  10, 242,   0,  16,   0, 
      4,   0,   0,   0,  70,  14, 
     16,   0,   2,   0,   0,   0, 
      2,  64,   0,   0,   8,   0, 
      0,   0,   8,   0,   0,   0, 
      8,   0,   0,   0,   8,   0, 
      0,   0,   1,   0,   0,  10, 
    242,   0,  16,   0,   4,   0, 
      0,   0,  70,  14,  16,   0, 
      4,   0,   0,   0,   2,  64, 
      0,   0, 255,   0, 255,   0, 
    255,   0, 255,   0, 255,   0, 
    255,   0, 255,   0, 255,   0, 
     30,   0,   0,   7, 242,   0, 
     16,   0,   2,   0,   0,   0, 
     70,  14,  16,   0,   3,   0, 
      0,   0,  70,  14,  16,   0, 
      4,   0,   0,   0,  21,   0, 
      0,   1,  31,   0,   4,   3, 
     58,   0,  16,   0,   0,   0, 
      0,   0,  85,   0,   0,  10, 
    242,   0,  16,   0,   3,   0, 
      0,   0,  70,  14,  16,   0, 
      2,   0,   0,   0,   2,  64, 
      0,   0,  16,   0,   0,   0, 
     16,   0,   0,   0,  16,   0, 
      0,   0,  16,   0,   0,   0, 
    140,   0,   0,  17, 242,   0, 
     16,   0,   2,   0,   0,   0, 
      2,  64,   0,   0,  16,   0, 
      0,   0,  16,   0,   0,   0, 
     16,   0,   0,   0,  16,   0, 
      0,   0,   2,  64,   0,   0, 
     16,   0,   0,   0,  16,   0, 
      0,   0,  16,   0,   0,   0, 
     16,   0,   0,   0,  70,  14, 
     16,   0,   2,   0,   0,   0, 
     70,  14,  16,   0,   3,   0, 
      0,   0,  21,   0,   0,   1, 
    164,   0,   0,   8, 242, 224, 
     33,   0,   0,   0,   0,   0, 
      0,   0,   0,   0, 166,  10, 
     16,   0,   1,   0,   0,   0, 
     70,  14,  16,   0,   2,   0, 
      0,   0,  62,   0,   0,   1, 
     83,  84,  65,  84, 148,   0, 
      0,   0, 125,   0,   0,   0, 
      6,   0,   0,   0,   0,   0, 
      0,   0,   1,   0,   0,   0, 
      0,   0,   0,   0,  46,   0, 
      0,   0,  25,   0,   0,   0, 
      5,   0,   0,   0,   8,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   2,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      4,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   2,   0,   0,   0
};
