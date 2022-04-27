// Generated with `xb buildshaders`.
#if 0
; SPIR-V
; Version: 1.0
; Generator: Khronos Glslang Reference Front End; 10
; Bound: 25179
; Schema: 0
               OpCapability Shader
          %1 = OpExtInstImport "GLSL.std.450"
               OpMemoryModel Logical GLSL450
               OpEntryPoint GLCompute %5663 "main" %gl_GlobalInvocationID
               OpExecutionMode %5663 LocalSize 4 32 1
               OpMemberDecorate %_struct_1161 0 Offset 0
               OpMemberDecorate %_struct_1161 1 Offset 4
               OpMemberDecorate %_struct_1161 2 Offset 8
               OpMemberDecorate %_struct_1161 3 Offset 12
               OpMemberDecorate %_struct_1161 4 Offset 16
               OpMemberDecorate %_struct_1161 5 Offset 28
               OpMemberDecorate %_struct_1161 6 Offset 32
               OpMemberDecorate %_struct_1161 7 Offset 36
               OpDecorate %_struct_1161 Block
               OpDecorate %5245 DescriptorSet 2
               OpDecorate %5245 Binding 0
               OpDecorate %gl_GlobalInvocationID BuiltIn GlobalInvocationId
               OpDecorate %_runtimearr_v4uint ArrayStride 16
               OpMemberDecorate %_struct_1972 0 NonWritable
               OpMemberDecorate %_struct_1972 0 Offset 0
               OpDecorate %_struct_1972 BufferBlock
               OpDecorate %4218 DescriptorSet 1
               OpDecorate %4218 Binding 0
               OpDecorate %_runtimearr_v4uint_0 ArrayStride 16
               OpMemberDecorate %_struct_1973 0 NonReadable
               OpMemberDecorate %_struct_1973 0 Offset 0
               OpDecorate %_struct_1973 BufferBlock
               OpDecorate %5134 DescriptorSet 0
               OpDecorate %5134 Binding 0
               OpDecorate %gl_WorkGroupSize BuiltIn WorkgroupSize
       %void = OpTypeVoid
       %1282 = OpTypeFunction %void
       %uint = OpTypeInt 32 0
     %v2uint = OpTypeVector %uint 2
     %v4uint = OpTypeVector %uint 4
        %int = OpTypeInt 32 1
      %v2int = OpTypeVector %int 2
      %v3int = OpTypeVector %int 3
       %bool = OpTypeBool
     %v3uint = OpTypeVector %uint 3
     %uint_0 = OpConstant %uint 0
    %uint_21 = OpConstant %uint 21
        %515 = OpConstantComposite %v4uint %uint_0 %uint_21 %uint_0 %uint_21
  %uint_1023 = OpConstant %uint 1023
  %uint_2047 = OpConstant %uint 2047
       %1539 = OpConstantComposite %v4uint %uint_1023 %uint_2047 %uint_1023 %uint_2047
     %uint_6 = OpConstant %uint 6
     %uint_5 = OpConstant %uint 5
        %179 = OpConstantComposite %v4uint %uint_6 %uint_5 %uint_6 %uint_5
     %uint_4 = OpConstant %uint 4
    %uint_27 = OpConstant %uint 27
        %791 = OpConstantComposite %v4uint %uint_4 %uint_27 %uint_4 %uint_27
    %uint_63 = OpConstant %uint 63
    %uint_31 = OpConstant %uint 31
       %2327 = OpConstantComposite %v4uint %uint_63 %uint_31 %uint_63 %uint_31
%uint_2096128 = OpConstant %uint 2096128
    %uint_11 = OpConstant %uint 11
%uint_2031616 = OpConstant %uint 2031616
     %uint_2 = OpConstant %uint 2
%uint_4294901760 = OpConstant %uint 4294901760
     %uint_1 = OpConstant %uint 1
     %uint_3 = OpConstant %uint 3
%uint_16711935 = OpConstant %uint 16711935
     %uint_8 = OpConstant %uint 8
%uint_4278255360 = OpConstant %uint 4278255360
    %uint_16 = OpConstant %uint 16
      %int_5 = OpConstant %int 5
      %int_7 = OpConstant %int 7
     %int_14 = OpConstant %int 14
      %int_2 = OpConstant %int 2
    %int_n16 = OpConstant %int -16
      %int_1 = OpConstant %int 1
     %int_15 = OpConstant %int 15
      %int_4 = OpConstant %int 4
   %int_n512 = OpConstant %int -512
      %int_3 = OpConstant %int 3
     %int_16 = OpConstant %int 16
    %int_448 = OpConstant %int 448
      %int_8 = OpConstant %int 8
      %int_6 = OpConstant %int 6
     %int_63 = OpConstant %int 63
%int_268435455 = OpConstant %int 268435455
     %int_n2 = OpConstant %int -2
    %uint_32 = OpConstant %uint 32
%_struct_1161 = OpTypeStruct %uint %uint %uint %uint %v3uint %uint %uint %uint
%_ptr_Uniform__struct_1161 = OpTypePointer Uniform %_struct_1161
       %5245 = OpVariable %_ptr_Uniform__struct_1161 Uniform
      %int_0 = OpConstant %int 0
%_ptr_Uniform_uint = OpTypePointer Uniform %uint
%_ptr_Uniform_v3uint = OpTypePointer Uniform %v3uint
%_ptr_Input_v3uint = OpTypePointer Input %v3uint
%gl_GlobalInvocationID = OpVariable %_ptr_Input_v3uint Input
       %2604 = OpConstantComposite %v3uint %uint_3 %uint_0 %uint_0
     %v2bool = OpTypeVector %bool 2
%_runtimearr_v4uint = OpTypeRuntimeArray %v4uint
%_struct_1972 = OpTypeStruct %_runtimearr_v4uint
%_ptr_Uniform__struct_1972 = OpTypePointer Uniform %_struct_1972
       %4218 = OpVariable %_ptr_Uniform__struct_1972 Uniform
%_ptr_Uniform_v4uint = OpTypePointer Uniform %v4uint
%_runtimearr_v4uint_0 = OpTypeRuntimeArray %v4uint
%_struct_1973 = OpTypeStruct %_runtimearr_v4uint_0
%_ptr_Uniform__struct_1973 = OpTypePointer Uniform %_struct_1973
       %5134 = OpVariable %_ptr_Uniform__struct_1973 Uniform
%gl_WorkGroupSize = OpConstantComposite %v3uint %uint_4 %uint_32 %uint_1
     %uint_9 = OpConstant %uint 9
       %2510 = OpConstantComposite %v4uint %uint_16711935 %uint_16711935 %uint_16711935 %uint_16711935
        %317 = OpConstantComposite %v4uint %uint_8 %uint_8 %uint_8 %uint_8
       %1838 = OpConstantComposite %v4uint %uint_4278255360 %uint_4278255360 %uint_4278255360 %uint_4278255360
        %749 = OpConstantComposite %v4uint %uint_16 %uint_16 %uint_16 %uint_16
       %2686 = OpConstantComposite %v2uint %uint_2096128 %uint_2096128
       %2038 = OpConstantComposite %v2uint %uint_11 %uint_11
       %2884 = OpConstantComposite %v2uint %uint_2031616 %uint_2031616
       %1578 = OpConstantComposite %v2uint %uint_4294901760 %uint_4294901760
        %200 = OpConstantNull %v2uint
       %5663 = OpFunction %void None %1282
      %15110 = OpLabel
               OpSelectionMerge %19578 None
               OpSwitch %uint_0 %15137
      %15137 = OpLabel
      %12591 = OpLoad %v3uint %gl_GlobalInvocationID
      %10229 = OpShiftLeftLogical %v3uint %12591 %2604
      %25178 = OpAccessChain %_ptr_Uniform_v3uint %5245 %int_4
      %22965 = OpLoad %v3uint %25178
      %18835 = OpVectorShuffle %v2uint %10229 %10229 0 1
       %6626 = OpVectorShuffle %v2uint %22965 %22965 0 1
      %17032 = OpUGreaterThanEqual %v2bool %18835 %6626
      %24679 = OpAny %bool %17032
               OpSelectionMerge %6282 DontFlatten
               OpBranchConditional %24679 %21992 %6282
      %21992 = OpLabel
               OpBranch %19578
       %6282 = OpLabel
       %6795 = OpBitcast %v3int %10229
      %18792 = OpAccessChain %_ptr_Uniform_uint %5245 %int_6
       %9788 = OpLoad %uint %18792
      %20376 = OpCompositeExtract %uint %22965 1
      %14692 = OpCompositeExtract %int %6795 0
      %22810 = OpIMul %int %14692 %int_8
       %6362 = OpCompositeExtract %int %6795 2
      %14505 = OpBitcast %int %20376
      %11279 = OpIMul %int %6362 %14505
      %17598 = OpCompositeExtract %int %6795 1
      %22228 = OpIAdd %int %11279 %17598
      %22405 = OpBitcast %int %9788
      %24535 = OpIMul %int %22228 %22405
       %7061 = OpIAdd %int %22810 %24535
      %19270 = OpBitcast %uint %7061
      %19460 = OpAccessChain %_ptr_Uniform_uint %5245 %int_5
      %22875 = OpLoad %uint %19460
       %8517 = OpIAdd %uint %19270 %22875
      %21670 = OpShiftRightLogical %uint %8517 %uint_4
      %20950 = OpAccessChain %_ptr_Uniform_uint %5245 %int_0
      %21411 = OpLoad %uint %20950
       %6381 = OpBitwiseAnd %uint %21411 %uint_1
      %10467 = OpINotEqual %bool %6381 %uint_0
               OpSelectionMerge %23266 DontFlatten
               OpBranchConditional %10467 %10108 %10765
      %10108 = OpLabel
      %23508 = OpBitwiseAnd %uint %21411 %uint_2
      %16300 = OpINotEqual %bool %23508 %uint_0
               OpSelectionMerge %7691 DontFlatten
               OpBranchConditional %16300 %12129 %25128
      %12129 = OpLabel
      %18210 = OpAccessChain %_ptr_Uniform_uint %5245 %int_2
      %15627 = OpLoad %uint %18210
      %22624 = OpAccessChain %_ptr_Uniform_uint %5245 %int_3
      %21535 = OpLoad %uint %22624
      %14923 = OpShiftRightArithmetic %int %17598 %int_4
      %18773 = OpShiftRightArithmetic %int %6362 %int_2
      %18759 = OpShiftRightLogical %uint %21535 %uint_4
       %6314 = OpBitcast %int %18759
      %21281 = OpIMul %int %18773 %6314
      %15143 = OpIAdd %int %14923 %21281
       %9032 = OpShiftRightLogical %uint %15627 %uint_5
      %14593 = OpBitcast %int %9032
       %8436 = OpIMul %int %15143 %14593
      %12986 = OpShiftRightArithmetic %int %14692 %int_5
      %24558 = OpIAdd %int %12986 %8436
       %8797 = OpShiftLeftLogical %int %24558 %uint_8
      %11510 = OpBitwiseAnd %int %8797 %int_268435455
      %18938 = OpShiftLeftLogical %int %11510 %int_1
      %19768 = OpBitwiseAnd %int %14692 %int_7
      %12600 = OpBitwiseAnd %int %17598 %int_6
      %17741 = OpShiftLeftLogical %int %12600 %int_2
      %17227 = OpIAdd %int %19768 %17741
       %7048 = OpShiftLeftLogical %int %17227 %uint_8
      %24035 = OpShiftRightArithmetic %int %7048 %int_6
       %8725 = OpShiftRightArithmetic %int %17598 %int_3
      %13731 = OpIAdd %int %8725 %18773
      %23052 = OpBitwiseAnd %int %13731 %int_1
      %16658 = OpShiftRightArithmetic %int %14692 %int_3
      %18794 = OpShiftLeftLogical %int %23052 %int_1
      %13501 = OpIAdd %int %16658 %18794
      %19165 = OpBitwiseAnd %int %13501 %int_3
      %21578 = OpShiftLeftLogical %int %19165 %int_1
      %15435 = OpIAdd %int %23052 %21578
      %13150 = OpBitwiseAnd %int %24035 %int_n16
      %20336 = OpIAdd %int %18938 %13150
      %23345 = OpShiftLeftLogical %int %20336 %int_1
      %23274 = OpBitwiseAnd %int %24035 %int_15
      %10332 = OpIAdd %int %23345 %23274
      %18356 = OpBitwiseAnd %int %6362 %int_3
      %21579 = OpShiftLeftLogical %int %18356 %uint_8
      %16727 = OpIAdd %int %10332 %21579
      %19166 = OpBitwiseAnd %int %17598 %int_1
      %21580 = OpShiftLeftLogical %int %19166 %int_4
      %16728 = OpIAdd %int %16727 %21580
      %20438 = OpBitwiseAnd %int %15435 %int_1
       %9987 = OpShiftLeftLogical %int %20438 %int_3
      %13106 = OpShiftRightArithmetic %int %16728 %int_6
      %14038 = OpBitwiseAnd %int %13106 %int_7
      %13330 = OpIAdd %int %9987 %14038
      %23346 = OpShiftLeftLogical %int %13330 %int_3
      %23217 = OpBitwiseAnd %int %15435 %int_n2
      %10908 = OpIAdd %int %23346 %23217
      %23347 = OpShiftLeftLogical %int %10908 %int_2
      %23218 = OpBitwiseAnd %int %16728 %int_n512
      %10909 = OpIAdd %int %23347 %23218
      %23348 = OpShiftLeftLogical %int %10909 %int_3
      %24224 = OpBitwiseAnd %int %16728 %int_63
      %21741 = OpIAdd %int %23348 %24224
               OpBranch %7691
      %25128 = OpLabel
       %6796 = OpBitcast %v2int %18835
      %18793 = OpAccessChain %_ptr_Uniform_uint %5245 %int_2
      %11954 = OpLoad %uint %18793
      %18756 = OpCompositeExtract %int %6796 0
      %19701 = OpShiftRightArithmetic %int %18756 %int_5
      %10055 = OpCompositeExtract %int %6796 1
      %16476 = OpShiftRightArithmetic %int %10055 %int_5
      %23373 = OpShiftRightLogical %uint %11954 %uint_5
       %6315 = OpBitcast %int %23373
      %21319 = OpIMul %int %16476 %6315
      %16222 = OpIAdd %int %19701 %21319
      %19086 = OpShiftLeftLogical %int %16222 %uint_9
      %10934 = OpBitwiseAnd %int %18756 %int_7
      %12601 = OpBitwiseAnd %int %10055 %int_14
      %17742 = OpShiftLeftLogical %int %12601 %int_2
      %17303 = OpIAdd %int %10934 %17742
       %6375 = OpShiftLeftLogical %int %17303 %uint_2
      %10161 = OpBitwiseAnd %int %6375 %int_n16
      %12150 = OpShiftLeftLogical %int %10161 %int_1
      %15436 = OpIAdd %int %19086 %12150
      %13207 = OpBitwiseAnd %int %6375 %int_15
      %19760 = OpIAdd %int %15436 %13207
      %18357 = OpBitwiseAnd %int %10055 %int_1
      %21581 = OpShiftLeftLogical %int %18357 %int_4
      %16729 = OpIAdd %int %19760 %21581
      %20514 = OpBitwiseAnd %int %16729 %int_n512
       %9238 = OpShiftLeftLogical %int %20514 %int_3
      %18995 = OpBitwiseAnd %int %10055 %int_16
      %12151 = OpShiftLeftLogical %int %18995 %int_7
      %16730 = OpIAdd %int %9238 %12151
      %19167 = OpBitwiseAnd %int %16729 %int_448
      %21582 = OpShiftLeftLogical %int %19167 %int_2
      %16708 = OpIAdd %int %16730 %21582
      %20611 = OpBitwiseAnd %int %10055 %int_8
      %16831 = OpShiftRightArithmetic %int %20611 %int_2
       %7916 = OpShiftRightArithmetic %int %18756 %int_3
      %13750 = OpIAdd %int %16831 %7916
      %21587 = OpBitwiseAnd %int %13750 %int_3
      %21583 = OpShiftLeftLogical %int %21587 %int_6
      %15437 = OpIAdd %int %16708 %21583
      %14157 = OpBitwiseAnd %int %16729 %int_63
      %12098 = OpIAdd %int %15437 %14157
               OpBranch %7691
       %7691 = OpLabel
      %10540 = OpPhi %int %21741 %12129 %12098 %25128
               OpBranch %23266
      %10765 = OpLabel
      %20632 = OpAccessChain %_ptr_Uniform_uint %5245 %int_2
      %15628 = OpLoad %uint %20632
      %21427 = OpAccessChain %_ptr_Uniform_uint %5245 %int_3
      %12014 = OpLoad %uint %21427
       %8199 = OpIMul %int %14692 %int_4
      %11736 = OpBitcast %int %12014
       %8690 = OpIMul %int %6362 %11736
       %8334 = OpIAdd %int %8690 %17598
       %8952 = OpBitcast %int %15628
       %7839 = OpIMul %int %8334 %8952
       %7984 = OpIAdd %int %8199 %7839
               OpBranch %23266
      %23266 = OpLabel
      %19748 = OpPhi %int %10540 %7691 %7984 %10765
      %24922 = OpAccessChain %_ptr_Uniform_uint %5245 %int_1
       %7502 = OpLoad %uint %24922
      %15686 = OpBitcast %int %7502
      %15579 = OpIAdd %int %15686 %19748
      %18556 = OpBitcast %uint %15579
      %21493 = OpShiftRightLogical %uint %18556 %uint_4
      %14997 = OpShiftRightLogical %uint %21411 %uint_2
       %8394 = OpBitwiseAnd %uint %14997 %uint_3
      %20727 = OpAccessChain %_ptr_Uniform_v4uint %4218 %int_0 %21493
       %8142 = OpLoad %v4uint %20727
      %13760 = OpIEqual %bool %8394 %uint_1
      %21366 = OpIEqual %bool %8394 %uint_2
      %22150 = OpLogicalOr %bool %13760 %21366
               OpSelectionMerge %13411 None
               OpBranchConditional %22150 %10583 %13411
      %10583 = OpLabel
      %18271 = OpBitwiseAnd %v4uint %8142 %2510
       %9425 = OpShiftLeftLogical %v4uint %18271 %317
      %20652 = OpBitwiseAnd %v4uint %8142 %1838
      %17549 = OpShiftRightLogical %v4uint %20652 %317
      %16376 = OpBitwiseOr %v4uint %9425 %17549
               OpBranch %13411
      %13411 = OpLabel
      %22649 = OpPhi %v4uint %8142 %23266 %16376 %10583
      %19638 = OpIEqual %bool %8394 %uint_3
      %15139 = OpLogicalOr %bool %21366 %19638
               OpSelectionMerge %11682 None
               OpBranchConditional %15139 %11064 %11682
      %11064 = OpLabel
      %24087 = OpShiftLeftLogical %v4uint %22649 %749
      %15335 = OpShiftRightLogical %v4uint %22649 %749
      %10728 = OpBitwiseOr %v4uint %24087 %15335
               OpBranch %11682
      %11682 = OpLabel
      %17668 = OpPhi %v4uint %22649 %13411 %10728 %11064
      %22862 = OpVectorShuffle %v2uint %17668 %17668 0 1
      %10663 = OpVectorShuffle %v4uint %17668 %200 0 0 1 1
       %9600 = OpShiftRightLogical %v4uint %10663 %515
       %7908 = OpBitwiseAnd %v4uint %9600 %1539
      %24647 = OpShiftLeftLogical %v4uint %7908 %179
      %22610 = OpShiftRightLogical %v4uint %10663 %791
      %21478 = OpBitwiseAnd %v4uint %22610 %2327
      %15532 = OpBitwiseOr %v4uint %24647 %21478
      %20095 = OpBitwiseAnd %v2uint %22862 %2686
      %22935 = OpShiftLeftLogical %v2uint %20095 %2038
      %17891 = OpBitwiseAnd %v2uint %22862 %2884
      %12396 = OpBitwiseOr %v2uint %22935 %17891
      %15605 = OpVectorShuffle %v2uint %15532 %15532 0 2
      %20952 = OpBitwiseOr %v2uint %15605 %12396
      %18889 = OpCompositeExtract %uint %20952 0
      %15556 = OpCompositeInsert %v4uint %18889 %15532 0
      %19814 = OpCompositeExtract %uint %20952 1
      %18666 = OpCompositeInsert %v4uint %19814 %15556 2
      %16343 = OpVectorShuffle %v2uint %18666 %18666 1 3
       %8917 = OpBitwiseOr %v2uint %16343 %1578
      %18890 = OpCompositeExtract %uint %8917 0
      %15557 = OpCompositeInsert %v4uint %18890 %18666 1
      %19815 = OpCompositeExtract %uint %8917 1
      %16424 = OpCompositeInsert %v4uint %19815 %15557 3
       %7219 = OpVectorShuffle %v2uint %17668 %17668 2 3
      %11272 = OpVectorShuffle %v4uint %17668 %200 2 2 3 3
       %9601 = OpShiftRightLogical %v4uint %11272 %515
       %7909 = OpBitwiseAnd %v4uint %9601 %1539
      %24648 = OpShiftLeftLogical %v4uint %7909 %179
      %22611 = OpShiftRightLogical %v4uint %11272 %791
      %21479 = OpBitwiseAnd %v4uint %22611 %2327
      %15533 = OpBitwiseOr %v4uint %24648 %21479
      %20096 = OpBitwiseAnd %v2uint %7219 %2686
      %22936 = OpShiftLeftLogical %v2uint %20096 %2038
      %17892 = OpBitwiseAnd %v2uint %7219 %2884
      %12397 = OpBitwiseOr %v2uint %22936 %17892
      %15606 = OpVectorShuffle %v2uint %15533 %15533 0 2
      %20953 = OpBitwiseOr %v2uint %15606 %12397
      %18891 = OpCompositeExtract %uint %20953 0
      %15558 = OpCompositeInsert %v4uint %18891 %15533 0
      %19816 = OpCompositeExtract %uint %20953 1
      %18667 = OpCompositeInsert %v4uint %19816 %15558 2
      %16344 = OpVectorShuffle %v2uint %18667 %18667 1 3
       %8918 = OpBitwiseOr %v2uint %16344 %1578
      %18892 = OpCompositeExtract %uint %8918 0
      %15559 = OpCompositeInsert %v4uint %18892 %18667 1
      %19548 = OpCompositeExtract %uint %8918 1
      %18523 = OpCompositeInsert %v4uint %19548 %15559 3
       %9182 = OpAccessChain %_ptr_Uniform_v4uint %5134 %int_0 %21670
               OpStore %9182 %16424
      %11457 = OpIAdd %uint %21670 %uint_1
      %23654 = OpAccessChain %_ptr_Uniform_v4uint %5134 %int_0 %11457
               OpStore %23654 %18523
      %16830 = OpSelect %uint %10467 %uint_32 %uint_16
      %22844 = OpShiftRightLogical %uint %16830 %uint_4
      %13947 = OpIAdd %uint %21493 %22844
      %22298 = OpAccessChain %_ptr_Uniform_v4uint %4218 %int_0 %13947
       %6578 = OpLoad %v4uint %22298
               OpSelectionMerge %14874 None
               OpBranchConditional %22150 %10584 %14874
      %10584 = OpLabel
      %18272 = OpBitwiseAnd %v4uint %6578 %2510
       %9426 = OpShiftLeftLogical %v4uint %18272 %317
      %20653 = OpBitwiseAnd %v4uint %6578 %1838
      %17550 = OpShiftRightLogical %v4uint %20653 %317
      %16377 = OpBitwiseOr %v4uint %9426 %17550
               OpBranch %14874
      %14874 = OpLabel
      %10924 = OpPhi %v4uint %6578 %11682 %16377 %10584
               OpSelectionMerge %11683 None
               OpBranchConditional %15139 %11065 %11683
      %11065 = OpLabel
      %24088 = OpShiftLeftLogical %v4uint %10924 %749
      %15336 = OpShiftRightLogical %v4uint %10924 %749
      %10729 = OpBitwiseOr %v4uint %24088 %15336
               OpBranch %11683
      %11683 = OpLabel
      %17669 = OpPhi %v4uint %10924 %14874 %10729 %11065
      %22863 = OpVectorShuffle %v2uint %17669 %17669 0 1
      %10664 = OpVectorShuffle %v4uint %17669 %200 0 0 1 1
       %9602 = OpShiftRightLogical %v4uint %10664 %515
       %7910 = OpBitwiseAnd %v4uint %9602 %1539
      %24649 = OpShiftLeftLogical %v4uint %7910 %179
      %22612 = OpShiftRightLogical %v4uint %10664 %791
      %21480 = OpBitwiseAnd %v4uint %22612 %2327
      %15534 = OpBitwiseOr %v4uint %24649 %21480
      %20097 = OpBitwiseAnd %v2uint %22863 %2686
      %22937 = OpShiftLeftLogical %v2uint %20097 %2038
      %17893 = OpBitwiseAnd %v2uint %22863 %2884
      %12398 = OpBitwiseOr %v2uint %22937 %17893
      %15607 = OpVectorShuffle %v2uint %15534 %15534 0 2
      %20954 = OpBitwiseOr %v2uint %15607 %12398
      %18893 = OpCompositeExtract %uint %20954 0
      %15560 = OpCompositeInsert %v4uint %18893 %15534 0
      %19817 = OpCompositeExtract %uint %20954 1
      %18668 = OpCompositeInsert %v4uint %19817 %15560 2
      %16345 = OpVectorShuffle %v2uint %18668 %18668 1 3
       %8919 = OpBitwiseOr %v2uint %16345 %1578
      %18894 = OpCompositeExtract %uint %8919 0
      %15561 = OpCompositeInsert %v4uint %18894 %18668 1
      %19818 = OpCompositeExtract %uint %8919 1
      %16425 = OpCompositeInsert %v4uint %19818 %15561 3
       %7220 = OpVectorShuffle %v2uint %17669 %17669 2 3
      %11273 = OpVectorShuffle %v4uint %17669 %200 2 2 3 3
       %9603 = OpShiftRightLogical %v4uint %11273 %515
       %7911 = OpBitwiseAnd %v4uint %9603 %1539
      %24650 = OpShiftLeftLogical %v4uint %7911 %179
      %22613 = OpShiftRightLogical %v4uint %11273 %791
      %21481 = OpBitwiseAnd %v4uint %22613 %2327
      %15535 = OpBitwiseOr %v4uint %24650 %21481
      %20098 = OpBitwiseAnd %v2uint %7220 %2686
      %22938 = OpShiftLeftLogical %v2uint %20098 %2038
      %17894 = OpBitwiseAnd %v2uint %7220 %2884
      %12399 = OpBitwiseOr %v2uint %22938 %17894
      %15608 = OpVectorShuffle %v2uint %15535 %15535 0 2
      %20955 = OpBitwiseOr %v2uint %15608 %12399
      %18895 = OpCompositeExtract %uint %20955 0
      %15562 = OpCompositeInsert %v4uint %18895 %15535 0
      %19819 = OpCompositeExtract %uint %20955 1
      %18669 = OpCompositeInsert %v4uint %19819 %15562 2
      %16346 = OpVectorShuffle %v2uint %18669 %18669 1 3
       %8920 = OpBitwiseOr %v2uint %16346 %1578
      %18896 = OpCompositeExtract %uint %8920 0
      %15563 = OpCompositeInsert %v4uint %18896 %18669 1
      %20745 = OpCompositeExtract %uint %8920 1
       %7681 = OpCompositeInsert %v4uint %20745 %15563 3
      %18781 = OpIAdd %uint %21670 %uint_2
       %7020 = OpAccessChain %_ptr_Uniform_v4uint %5134 %int_0 %18781
               OpStore %7020 %16425
      %11458 = OpIAdd %uint %21670 %uint_3
      %25174 = OpAccessChain %_ptr_Uniform_v4uint %5134 %int_0 %11458
               OpStore %25174 %7681
               OpBranch %19578
      %19578 = OpLabel
               OpReturn
               OpFunctionEnd
#endif

const uint32_t texture_load_r10g11b11_rgba16_cs[] = {
    0x07230203, 0x00010000, 0x0008000A, 0x0000625B, 0x00000000, 0x00020011,
    0x00000001, 0x0006000B, 0x00000001, 0x4C534C47, 0x6474732E, 0x3035342E,
    0x00000000, 0x0003000E, 0x00000000, 0x00000001, 0x0006000F, 0x00000005,
    0x0000161F, 0x6E69616D, 0x00000000, 0x00000F48, 0x00060010, 0x0000161F,
    0x00000011, 0x00000004, 0x00000020, 0x00000001, 0x00050048, 0x00000489,
    0x00000000, 0x00000023, 0x00000000, 0x00050048, 0x00000489, 0x00000001,
    0x00000023, 0x00000004, 0x00050048, 0x00000489, 0x00000002, 0x00000023,
    0x00000008, 0x00050048, 0x00000489, 0x00000003, 0x00000023, 0x0000000C,
    0x00050048, 0x00000489, 0x00000004, 0x00000023, 0x00000010, 0x00050048,
    0x00000489, 0x00000005, 0x00000023, 0x0000001C, 0x00050048, 0x00000489,
    0x00000006, 0x00000023, 0x00000020, 0x00050048, 0x00000489, 0x00000007,
    0x00000023, 0x00000024, 0x00030047, 0x00000489, 0x00000002, 0x00040047,
    0x0000147D, 0x00000022, 0x00000002, 0x00040047, 0x0000147D, 0x00000021,
    0x00000000, 0x00040047, 0x00000F48, 0x0000000B, 0x0000001C, 0x00040047,
    0x000007DC, 0x00000006, 0x00000010, 0x00040048, 0x000007B4, 0x00000000,
    0x00000018, 0x00050048, 0x000007B4, 0x00000000, 0x00000023, 0x00000000,
    0x00030047, 0x000007B4, 0x00000003, 0x00040047, 0x0000107A, 0x00000022,
    0x00000001, 0x00040047, 0x0000107A, 0x00000021, 0x00000000, 0x00040047,
    0x000007DD, 0x00000006, 0x00000010, 0x00040048, 0x000007B5, 0x00000000,
    0x00000019, 0x00050048, 0x000007B5, 0x00000000, 0x00000023, 0x00000000,
    0x00030047, 0x000007B5, 0x00000003, 0x00040047, 0x0000140E, 0x00000022,
    0x00000000, 0x00040047, 0x0000140E, 0x00000021, 0x00000000, 0x00040047,
    0x00000BC3, 0x0000000B, 0x00000019, 0x00020013, 0x00000008, 0x00030021,
    0x00000502, 0x00000008, 0x00040015, 0x0000000B, 0x00000020, 0x00000000,
    0x00040017, 0x00000011, 0x0000000B, 0x00000002, 0x00040017, 0x00000017,
    0x0000000B, 0x00000004, 0x00040015, 0x0000000C, 0x00000020, 0x00000001,
    0x00040017, 0x00000012, 0x0000000C, 0x00000002, 0x00040017, 0x00000016,
    0x0000000C, 0x00000003, 0x00020014, 0x00000009, 0x00040017, 0x00000014,
    0x0000000B, 0x00000003, 0x0004002B, 0x0000000B, 0x00000A0A, 0x00000000,
    0x0004002B, 0x0000000B, 0x00000A49, 0x00000015, 0x0007002C, 0x00000017,
    0x00000203, 0x00000A0A, 0x00000A49, 0x00000A0A, 0x00000A49, 0x0004002B,
    0x0000000B, 0x00000A44, 0x000003FF, 0x0004002B, 0x0000000B, 0x00000A81,
    0x000007FF, 0x0007002C, 0x00000017, 0x00000603, 0x00000A44, 0x00000A81,
    0x00000A44, 0x00000A81, 0x0004002B, 0x0000000B, 0x00000A1C, 0x00000006,
    0x0004002B, 0x0000000B, 0x00000A19, 0x00000005, 0x0007002C, 0x00000017,
    0x000000B3, 0x00000A1C, 0x00000A19, 0x00000A1C, 0x00000A19, 0x0004002B,
    0x0000000B, 0x00000A16, 0x00000004, 0x0004002B, 0x0000000B, 0x00000A5B,
    0x0000001B, 0x0007002C, 0x00000017, 0x00000317, 0x00000A16, 0x00000A5B,
    0x00000A16, 0x00000A5B, 0x0004002B, 0x0000000B, 0x00000AC7, 0x0000003F,
    0x0004002B, 0x0000000B, 0x00000A67, 0x0000001F, 0x0007002C, 0x00000017,
    0x00000917, 0x00000AC7, 0x00000A67, 0x00000AC7, 0x00000A67, 0x0004002B,
    0x0000000B, 0x000003CF, 0x001FFC00, 0x0004002B, 0x0000000B, 0x00000A2B,
    0x0000000B, 0x0004002B, 0x0000000B, 0x0000008F, 0x001F0000, 0x0004002B,
    0x0000000B, 0x00000A10, 0x00000002, 0x0004002B, 0x0000000B, 0x0000068D,
    0xFFFF0000, 0x0004002B, 0x0000000B, 0x00000A0D, 0x00000001, 0x0004002B,
    0x0000000B, 0x00000A13, 0x00000003, 0x0004002B, 0x0000000B, 0x000008A6,
    0x00FF00FF, 0x0004002B, 0x0000000B, 0x00000A22, 0x00000008, 0x0004002B,
    0x0000000B, 0x000005FD, 0xFF00FF00, 0x0004002B, 0x0000000B, 0x00000A3A,
    0x00000010, 0x0004002B, 0x0000000C, 0x00000A1A, 0x00000005, 0x0004002B,
    0x0000000C, 0x00000A20, 0x00000007, 0x0004002B, 0x0000000C, 0x00000A35,
    0x0000000E, 0x0004002B, 0x0000000C, 0x00000A11, 0x00000002, 0x0004002B,
    0x0000000C, 0x000009DB, 0xFFFFFFF0, 0x0004002B, 0x0000000C, 0x00000A0E,
    0x00000001, 0x0004002B, 0x0000000C, 0x00000A38, 0x0000000F, 0x0004002B,
    0x0000000C, 0x00000A17, 0x00000004, 0x0004002B, 0x0000000C, 0x0000040B,
    0xFFFFFE00, 0x0004002B, 0x0000000C, 0x00000A14, 0x00000003, 0x0004002B,
    0x0000000C, 0x00000A3B, 0x00000010, 0x0004002B, 0x0000000C, 0x00000388,
    0x000001C0, 0x0004002B, 0x0000000C, 0x00000A23, 0x00000008, 0x0004002B,
    0x0000000C, 0x00000A1D, 0x00000006, 0x0004002B, 0x0000000C, 0x00000AC8,
    0x0000003F, 0x0004002B, 0x0000000C, 0x0000078B, 0x0FFFFFFF, 0x0004002B,
    0x0000000C, 0x00000A05, 0xFFFFFFFE, 0x0004002B, 0x0000000B, 0x00000A6A,
    0x00000020, 0x000A001E, 0x00000489, 0x0000000B, 0x0000000B, 0x0000000B,
    0x0000000B, 0x00000014, 0x0000000B, 0x0000000B, 0x0000000B, 0x00040020,
    0x00000706, 0x00000002, 0x00000489, 0x0004003B, 0x00000706, 0x0000147D,
    0x00000002, 0x0004002B, 0x0000000C, 0x00000A0B, 0x00000000, 0x00040020,
    0x00000288, 0x00000002, 0x0000000B, 0x00040020, 0x00000291, 0x00000002,
    0x00000014, 0x00040020, 0x00000292, 0x00000001, 0x00000014, 0x0004003B,
    0x00000292, 0x00000F48, 0x00000001, 0x0006002C, 0x00000014, 0x00000A2C,
    0x00000A13, 0x00000A0A, 0x00000A0A, 0x00040017, 0x0000000F, 0x00000009,
    0x00000002, 0x0003001D, 0x000007DC, 0x00000017, 0x0003001E, 0x000007B4,
    0x000007DC, 0x00040020, 0x00000A31, 0x00000002, 0x000007B4, 0x0004003B,
    0x00000A31, 0x0000107A, 0x00000002, 0x00040020, 0x00000294, 0x00000002,
    0x00000017, 0x0003001D, 0x000007DD, 0x00000017, 0x0003001E, 0x000007B5,
    0x000007DD, 0x00040020, 0x00000A32, 0x00000002, 0x000007B5, 0x0004003B,
    0x00000A32, 0x0000140E, 0x00000002, 0x0006002C, 0x00000014, 0x00000BC3,
    0x00000A16, 0x00000A6A, 0x00000A0D, 0x0004002B, 0x0000000B, 0x00000A25,
    0x00000009, 0x0007002C, 0x00000017, 0x000009CE, 0x000008A6, 0x000008A6,
    0x000008A6, 0x000008A6, 0x0007002C, 0x00000017, 0x0000013D, 0x00000A22,
    0x00000A22, 0x00000A22, 0x00000A22, 0x0007002C, 0x00000017, 0x0000072E,
    0x000005FD, 0x000005FD, 0x000005FD, 0x000005FD, 0x0007002C, 0x00000017,
    0x000002ED, 0x00000A3A, 0x00000A3A, 0x00000A3A, 0x00000A3A, 0x0005002C,
    0x00000011, 0x00000A7E, 0x000003CF, 0x000003CF, 0x0005002C, 0x00000011,
    0x000007F6, 0x00000A2B, 0x00000A2B, 0x0005002C, 0x00000011, 0x00000B44,
    0x0000008F, 0x0000008F, 0x0005002C, 0x00000011, 0x0000062A, 0x0000068D,
    0x0000068D, 0x0003002E, 0x00000011, 0x000000C8, 0x00050036, 0x00000008,
    0x0000161F, 0x00000000, 0x00000502, 0x000200F8, 0x00003B06, 0x000300F7,
    0x00004C7A, 0x00000000, 0x000300FB, 0x00000A0A, 0x00003B21, 0x000200F8,
    0x00003B21, 0x0004003D, 0x00000014, 0x0000312F, 0x00000F48, 0x000500C4,
    0x00000014, 0x000027F5, 0x0000312F, 0x00000A2C, 0x00050041, 0x00000291,
    0x0000625A, 0x0000147D, 0x00000A17, 0x0004003D, 0x00000014, 0x000059B5,
    0x0000625A, 0x0007004F, 0x00000011, 0x00004993, 0x000027F5, 0x000027F5,
    0x00000000, 0x00000001, 0x0007004F, 0x00000011, 0x000019E2, 0x000059B5,
    0x000059B5, 0x00000000, 0x00000001, 0x000500AE, 0x0000000F, 0x00004288,
    0x00004993, 0x000019E2, 0x0004009A, 0x00000009, 0x00006067, 0x00004288,
    0x000300F7, 0x0000188A, 0x00000002, 0x000400FA, 0x00006067, 0x000055E8,
    0x0000188A, 0x000200F8, 0x000055E8, 0x000200F9, 0x00004C7A, 0x000200F8,
    0x0000188A, 0x0004007C, 0x00000016, 0x00001A8B, 0x000027F5, 0x00050041,
    0x00000288, 0x00004968, 0x0000147D, 0x00000A1D, 0x0004003D, 0x0000000B,
    0x0000263C, 0x00004968, 0x00050051, 0x0000000B, 0x00004F98, 0x000059B5,
    0x00000001, 0x00050051, 0x0000000C, 0x00003964, 0x00001A8B, 0x00000000,
    0x00050084, 0x0000000C, 0x0000591A, 0x00003964, 0x00000A23, 0x00050051,
    0x0000000C, 0x000018DA, 0x00001A8B, 0x00000002, 0x0004007C, 0x0000000C,
    0x000038A9, 0x00004F98, 0x00050084, 0x0000000C, 0x00002C0F, 0x000018DA,
    0x000038A9, 0x00050051, 0x0000000C, 0x000044BE, 0x00001A8B, 0x00000001,
    0x00050080, 0x0000000C, 0x000056D4, 0x00002C0F, 0x000044BE, 0x0004007C,
    0x0000000C, 0x00005785, 0x0000263C, 0x00050084, 0x0000000C, 0x00005FD7,
    0x000056D4, 0x00005785, 0x00050080, 0x0000000C, 0x00001B95, 0x0000591A,
    0x00005FD7, 0x0004007C, 0x0000000B, 0x00004B46, 0x00001B95, 0x00050041,
    0x00000288, 0x00004C04, 0x0000147D, 0x00000A1A, 0x0004003D, 0x0000000B,
    0x0000595B, 0x00004C04, 0x00050080, 0x0000000B, 0x00002145, 0x00004B46,
    0x0000595B, 0x000500C2, 0x0000000B, 0x000054A6, 0x00002145, 0x00000A16,
    0x00050041, 0x00000288, 0x000051D6, 0x0000147D, 0x00000A0B, 0x0004003D,
    0x0000000B, 0x000053A3, 0x000051D6, 0x000500C7, 0x0000000B, 0x000018ED,
    0x000053A3, 0x00000A0D, 0x000500AB, 0x00000009, 0x000028E3, 0x000018ED,
    0x00000A0A, 0x000300F7, 0x00005AE2, 0x00000002, 0x000400FA, 0x000028E3,
    0x0000277C, 0x00002A0D, 0x000200F8, 0x0000277C, 0x000500C7, 0x0000000B,
    0x00005BD4, 0x000053A3, 0x00000A10, 0x000500AB, 0x00000009, 0x00003FAC,
    0x00005BD4, 0x00000A0A, 0x000300F7, 0x00001E0B, 0x00000002, 0x000400FA,
    0x00003FAC, 0x00002F61, 0x00006228, 0x000200F8, 0x00002F61, 0x00050041,
    0x00000288, 0x00004722, 0x0000147D, 0x00000A11, 0x0004003D, 0x0000000B,
    0x00003D0B, 0x00004722, 0x00050041, 0x00000288, 0x00005860, 0x0000147D,
    0x00000A14, 0x0004003D, 0x0000000B, 0x0000541F, 0x00005860, 0x000500C3,
    0x0000000C, 0x00003A4B, 0x000044BE, 0x00000A17, 0x000500C3, 0x0000000C,
    0x00004955, 0x000018DA, 0x00000A11, 0x000500C2, 0x0000000B, 0x00004947,
    0x0000541F, 0x00000A16, 0x0004007C, 0x0000000C, 0x000018AA, 0x00004947,
    0x00050084, 0x0000000C, 0x00005321, 0x00004955, 0x000018AA, 0x00050080,
    0x0000000C, 0x00003B27, 0x00003A4B, 0x00005321, 0x000500C2, 0x0000000B,
    0x00002348, 0x00003D0B, 0x00000A19, 0x0004007C, 0x0000000C, 0x00003901,
    0x00002348, 0x00050084, 0x0000000C, 0x000020F4, 0x00003B27, 0x00003901,
    0x000500C3, 0x0000000C, 0x000032BA, 0x00003964, 0x00000A1A, 0x00050080,
    0x0000000C, 0x00005FEE, 0x000032BA, 0x000020F4, 0x000500C4, 0x0000000C,
    0x0000225D, 0x00005FEE, 0x00000A22, 0x000500C7, 0x0000000C, 0x00002CF6,
    0x0000225D, 0x0000078B, 0x000500C4, 0x0000000C, 0x000049FA, 0x00002CF6,
    0x00000A0E, 0x000500C7, 0x0000000C, 0x00004D38, 0x00003964, 0x00000A20,
    0x000500C7, 0x0000000C, 0x00003138, 0x000044BE, 0x00000A1D, 0x000500C4,
    0x0000000C, 0x0000454D, 0x00003138, 0x00000A11, 0x00050080, 0x0000000C,
    0x0000434B, 0x00004D38, 0x0000454D, 0x000500C4, 0x0000000C, 0x00001B88,
    0x0000434B, 0x00000A22, 0x000500C3, 0x0000000C, 0x00005DE3, 0x00001B88,
    0x00000A1D, 0x000500C3, 0x0000000C, 0x00002215, 0x000044BE, 0x00000A14,
    0x00050080, 0x0000000C, 0x000035A3, 0x00002215, 0x00004955, 0x000500C7,
    0x0000000C, 0x00005A0C, 0x000035A3, 0x00000A0E, 0x000500C3, 0x0000000C,
    0x00004112, 0x00003964, 0x00000A14, 0x000500C4, 0x0000000C, 0x0000496A,
    0x00005A0C, 0x00000A0E, 0x00050080, 0x0000000C, 0x000034BD, 0x00004112,
    0x0000496A, 0x000500C7, 0x0000000C, 0x00004ADD, 0x000034BD, 0x00000A14,
    0x000500C4, 0x0000000C, 0x0000544A, 0x00004ADD, 0x00000A0E, 0x00050080,
    0x0000000C, 0x00003C4B, 0x00005A0C, 0x0000544A, 0x000500C7, 0x0000000C,
    0x0000335E, 0x00005DE3, 0x000009DB, 0x00050080, 0x0000000C, 0x00004F70,
    0x000049FA, 0x0000335E, 0x000500C4, 0x0000000C, 0x00005B31, 0x00004F70,
    0x00000A0E, 0x000500C7, 0x0000000C, 0x00005AEA, 0x00005DE3, 0x00000A38,
    0x00050080, 0x0000000C, 0x0000285C, 0x00005B31, 0x00005AEA, 0x000500C7,
    0x0000000C, 0x000047B4, 0x000018DA, 0x00000A14, 0x000500C4, 0x0000000C,
    0x0000544B, 0x000047B4, 0x00000A22, 0x00050080, 0x0000000C, 0x00004157,
    0x0000285C, 0x0000544B, 0x000500C7, 0x0000000C, 0x00004ADE, 0x000044BE,
    0x00000A0E, 0x000500C4, 0x0000000C, 0x0000544C, 0x00004ADE, 0x00000A17,
    0x00050080, 0x0000000C, 0x00004158, 0x00004157, 0x0000544C, 0x000500C7,
    0x0000000C, 0x00004FD6, 0x00003C4B, 0x00000A0E, 0x000500C4, 0x0000000C,
    0x00002703, 0x00004FD6, 0x00000A14, 0x000500C3, 0x0000000C, 0x00003332,
    0x00004158, 0x00000A1D, 0x000500C7, 0x0000000C, 0x000036D6, 0x00003332,
    0x00000A20, 0x00050080, 0x0000000C, 0x00003412, 0x00002703, 0x000036D6,
    0x000500C4, 0x0000000C, 0x00005B32, 0x00003412, 0x00000A14, 0x000500C7,
    0x0000000C, 0x00005AB1, 0x00003C4B, 0x00000A05, 0x00050080, 0x0000000C,
    0x00002A9C, 0x00005B32, 0x00005AB1, 0x000500C4, 0x0000000C, 0x00005B33,
    0x00002A9C, 0x00000A11, 0x000500C7, 0x0000000C, 0x00005AB2, 0x00004158,
    0x0000040B, 0x00050080, 0x0000000C, 0x00002A9D, 0x00005B33, 0x00005AB2,
    0x000500C4, 0x0000000C, 0x00005B34, 0x00002A9D, 0x00000A14, 0x000500C7,
    0x0000000C, 0x00005EA0, 0x00004158, 0x00000AC8, 0x00050080, 0x0000000C,
    0x000054ED, 0x00005B34, 0x00005EA0, 0x000200F9, 0x00001E0B, 0x000200F8,
    0x00006228, 0x0004007C, 0x00000012, 0x00001A8C, 0x00004993, 0x00050041,
    0x00000288, 0x00004969, 0x0000147D, 0x00000A11, 0x0004003D, 0x0000000B,
    0x00002EB2, 0x00004969, 0x00050051, 0x0000000C, 0x00004944, 0x00001A8C,
    0x00000000, 0x000500C3, 0x0000000C, 0x00004CF5, 0x00004944, 0x00000A1A,
    0x00050051, 0x0000000C, 0x00002747, 0x00001A8C, 0x00000001, 0x000500C3,
    0x0000000C, 0x0000405C, 0x00002747, 0x00000A1A, 0x000500C2, 0x0000000B,
    0x00005B4D, 0x00002EB2, 0x00000A19, 0x0004007C, 0x0000000C, 0x000018AB,
    0x00005B4D, 0x00050084, 0x0000000C, 0x00005347, 0x0000405C, 0x000018AB,
    0x00050080, 0x0000000C, 0x00003F5E, 0x00004CF5, 0x00005347, 0x000500C4,
    0x0000000C, 0x00004A8E, 0x00003F5E, 0x00000A25, 0x000500C7, 0x0000000C,
    0x00002AB6, 0x00004944, 0x00000A20, 0x000500C7, 0x0000000C, 0x00003139,
    0x00002747, 0x00000A35, 0x000500C4, 0x0000000C, 0x0000454E, 0x00003139,
    0x00000A11, 0x00050080, 0x0000000C, 0x00004397, 0x00002AB6, 0x0000454E,
    0x000500C4, 0x0000000C, 0x000018E7, 0x00004397, 0x00000A10, 0x000500C7,
    0x0000000C, 0x000027B1, 0x000018E7, 0x000009DB, 0x000500C4, 0x0000000C,
    0x00002F76, 0x000027B1, 0x00000A0E, 0x00050080, 0x0000000C, 0x00003C4C,
    0x00004A8E, 0x00002F76, 0x000500C7, 0x0000000C, 0x00003397, 0x000018E7,
    0x00000A38, 0x00050080, 0x0000000C, 0x00004D30, 0x00003C4C, 0x00003397,
    0x000500C7, 0x0000000C, 0x000047B5, 0x00002747, 0x00000A0E, 0x000500C4,
    0x0000000C, 0x0000544D, 0x000047B5, 0x00000A17, 0x00050080, 0x0000000C,
    0x00004159, 0x00004D30, 0x0000544D, 0x000500C7, 0x0000000C, 0x00005022,
    0x00004159, 0x0000040B, 0x000500C4, 0x0000000C, 0x00002416, 0x00005022,
    0x00000A14, 0x000500C7, 0x0000000C, 0x00004A33, 0x00002747, 0x00000A3B,
    0x000500C4, 0x0000000C, 0x00002F77, 0x00004A33, 0x00000A20, 0x00050080,
    0x0000000C, 0x0000415A, 0x00002416, 0x00002F77, 0x000500C7, 0x0000000C,
    0x00004ADF, 0x00004159, 0x00000388, 0x000500C4, 0x0000000C, 0x0000544E,
    0x00004ADF, 0x00000A11, 0x00050080, 0x0000000C, 0x00004144, 0x0000415A,
    0x0000544E, 0x000500C7, 0x0000000C, 0x00005083, 0x00002747, 0x00000A23,
    0x000500C3, 0x0000000C, 0x000041BF, 0x00005083, 0x00000A11, 0x000500C3,
    0x0000000C, 0x00001EEC, 0x00004944, 0x00000A14, 0x00050080, 0x0000000C,
    0x000035B6, 0x000041BF, 0x00001EEC, 0x000500C7, 0x0000000C, 0x00005453,
    0x000035B6, 0x00000A14, 0x000500C4, 0x0000000C, 0x0000544F, 0x00005453,
    0x00000A1D, 0x00050080, 0x0000000C, 0x00003C4D, 0x00004144, 0x0000544F,
    0x000500C7, 0x0000000C, 0x0000374D, 0x00004159, 0x00000AC8, 0x00050080,
    0x0000000C, 0x00002F42, 0x00003C4D, 0x0000374D, 0x000200F9, 0x00001E0B,
    0x000200F8, 0x00001E0B, 0x000700F5, 0x0000000C, 0x0000292C, 0x000054ED,
    0x00002F61, 0x00002F42, 0x00006228, 0x000200F9, 0x00005AE2, 0x000200F8,
    0x00002A0D, 0x00050041, 0x00000288, 0x00005098, 0x0000147D, 0x00000A11,
    0x0004003D, 0x0000000B, 0x00003D0C, 0x00005098, 0x00050041, 0x00000288,
    0x000053B3, 0x0000147D, 0x00000A14, 0x0004003D, 0x0000000B, 0x00002EEE,
    0x000053B3, 0x00050084, 0x0000000C, 0x00002007, 0x00003964, 0x00000A17,
    0x0004007C, 0x0000000C, 0x00002DD8, 0x00002EEE, 0x00050084, 0x0000000C,
    0x000021F2, 0x000018DA, 0x00002DD8, 0x00050080, 0x0000000C, 0x0000208E,
    0x000021F2, 0x000044BE, 0x0004007C, 0x0000000C, 0x000022F8, 0x00003D0C,
    0x00050084, 0x0000000C, 0x00001E9F, 0x0000208E, 0x000022F8, 0x00050080,
    0x0000000C, 0x00001F30, 0x00002007, 0x00001E9F, 0x000200F9, 0x00005AE2,
    0x000200F8, 0x00005AE2, 0x000700F5, 0x0000000C, 0x00004D24, 0x0000292C,
    0x00001E0B, 0x00001F30, 0x00002A0D, 0x00050041, 0x00000288, 0x0000615A,
    0x0000147D, 0x00000A0E, 0x0004003D, 0x0000000B, 0x00001D4E, 0x0000615A,
    0x0004007C, 0x0000000C, 0x00003D46, 0x00001D4E, 0x00050080, 0x0000000C,
    0x00003CDB, 0x00003D46, 0x00004D24, 0x0004007C, 0x0000000B, 0x0000487C,
    0x00003CDB, 0x000500C2, 0x0000000B, 0x000053F5, 0x0000487C, 0x00000A16,
    0x000500C2, 0x0000000B, 0x00003A95, 0x000053A3, 0x00000A10, 0x000500C7,
    0x0000000B, 0x000020CA, 0x00003A95, 0x00000A13, 0x00060041, 0x00000294,
    0x000050F7, 0x0000107A, 0x00000A0B, 0x000053F5, 0x0004003D, 0x00000017,
    0x00001FCE, 0x000050F7, 0x000500AA, 0x00000009, 0x000035C0, 0x000020CA,
    0x00000A0D, 0x000500AA, 0x00000009, 0x00005376, 0x000020CA, 0x00000A10,
    0x000500A6, 0x00000009, 0x00005686, 0x000035C0, 0x00005376, 0x000300F7,
    0x00003463, 0x00000000, 0x000400FA, 0x00005686, 0x00002957, 0x00003463,
    0x000200F8, 0x00002957, 0x000500C7, 0x00000017, 0x0000475F, 0x00001FCE,
    0x000009CE, 0x000500C4, 0x00000017, 0x000024D1, 0x0000475F, 0x0000013D,
    0x000500C7, 0x00000017, 0x000050AC, 0x00001FCE, 0x0000072E, 0x000500C2,
    0x00000017, 0x0000448D, 0x000050AC, 0x0000013D, 0x000500C5, 0x00000017,
    0x00003FF8, 0x000024D1, 0x0000448D, 0x000200F9, 0x00003463, 0x000200F8,
    0x00003463, 0x000700F5, 0x00000017, 0x00005879, 0x00001FCE, 0x00005AE2,
    0x00003FF8, 0x00002957, 0x000500AA, 0x00000009, 0x00004CB6, 0x000020CA,
    0x00000A13, 0x000500A6, 0x00000009, 0x00003B23, 0x00005376, 0x00004CB6,
    0x000300F7, 0x00002DA2, 0x00000000, 0x000400FA, 0x00003B23, 0x00002B38,
    0x00002DA2, 0x000200F8, 0x00002B38, 0x000500C4, 0x00000017, 0x00005E17,
    0x00005879, 0x000002ED, 0x000500C2, 0x00000017, 0x00003BE7, 0x00005879,
    0x000002ED, 0x000500C5, 0x00000017, 0x000029E8, 0x00005E17, 0x00003BE7,
    0x000200F9, 0x00002DA2, 0x000200F8, 0x00002DA2, 0x000700F5, 0x00000017,
    0x00004504, 0x00005879, 0x00003463, 0x000029E8, 0x00002B38, 0x0007004F,
    0x00000011, 0x0000594E, 0x00004504, 0x00004504, 0x00000000, 0x00000001,
    0x0009004F, 0x00000017, 0x000029A7, 0x00004504, 0x000000C8, 0x00000000,
    0x00000000, 0x00000001, 0x00000001, 0x000500C2, 0x00000017, 0x00002580,
    0x000029A7, 0x00000203, 0x000500C7, 0x00000017, 0x00001EE4, 0x00002580,
    0x00000603, 0x000500C4, 0x00000017, 0x00006047, 0x00001EE4, 0x000000B3,
    0x000500C2, 0x00000017, 0x00005852, 0x000029A7, 0x00000317, 0x000500C7,
    0x00000017, 0x000053E6, 0x00005852, 0x00000917, 0x000500C5, 0x00000017,
    0x00003CAC, 0x00006047, 0x000053E6, 0x000500C7, 0x00000011, 0x00004E7F,
    0x0000594E, 0x00000A7E, 0x000500C4, 0x00000011, 0x00005997, 0x00004E7F,
    0x000007F6, 0x000500C7, 0x00000011, 0x000045E3, 0x0000594E, 0x00000B44,
    0x000500C5, 0x00000011, 0x0000306C, 0x00005997, 0x000045E3, 0x0007004F,
    0x00000011, 0x00003CF5, 0x00003CAC, 0x00003CAC, 0x00000000, 0x00000002,
    0x000500C5, 0x00000011, 0x000051D8, 0x00003CF5, 0x0000306C, 0x00050051,
    0x0000000B, 0x000049C9, 0x000051D8, 0x00000000, 0x00060052, 0x00000017,
    0x00003CC4, 0x000049C9, 0x00003CAC, 0x00000000, 0x00050051, 0x0000000B,
    0x00004D66, 0x000051D8, 0x00000001, 0x00060052, 0x00000017, 0x000048EA,
    0x00004D66, 0x00003CC4, 0x00000002, 0x0007004F, 0x00000011, 0x00003FD7,
    0x000048EA, 0x000048EA, 0x00000001, 0x00000003, 0x000500C5, 0x00000011,
    0x000022D5, 0x00003FD7, 0x0000062A, 0x00050051, 0x0000000B, 0x000049CA,
    0x000022D5, 0x00000000, 0x00060052, 0x00000017, 0x00003CC5, 0x000049CA,
    0x000048EA, 0x00000001, 0x00050051, 0x0000000B, 0x00004D67, 0x000022D5,
    0x00000001, 0x00060052, 0x00000017, 0x00004028, 0x00004D67, 0x00003CC5,
    0x00000003, 0x0007004F, 0x00000011, 0x00001C33, 0x00004504, 0x00004504,
    0x00000002, 0x00000003, 0x0009004F, 0x00000017, 0x00002C08, 0x00004504,
    0x000000C8, 0x00000002, 0x00000002, 0x00000003, 0x00000003, 0x000500C2,
    0x00000017, 0x00002581, 0x00002C08, 0x00000203, 0x000500C7, 0x00000017,
    0x00001EE5, 0x00002581, 0x00000603, 0x000500C4, 0x00000017, 0x00006048,
    0x00001EE5, 0x000000B3, 0x000500C2, 0x00000017, 0x00005853, 0x00002C08,
    0x00000317, 0x000500C7, 0x00000017, 0x000053E7, 0x00005853, 0x00000917,
    0x000500C5, 0x00000017, 0x00003CAD, 0x00006048, 0x000053E7, 0x000500C7,
    0x00000011, 0x00004E80, 0x00001C33, 0x00000A7E, 0x000500C4, 0x00000011,
    0x00005998, 0x00004E80, 0x000007F6, 0x000500C7, 0x00000011, 0x000045E4,
    0x00001C33, 0x00000B44, 0x000500C5, 0x00000011, 0x0000306D, 0x00005998,
    0x000045E4, 0x0007004F, 0x00000011, 0x00003CF6, 0x00003CAD, 0x00003CAD,
    0x00000000, 0x00000002, 0x000500C5, 0x00000011, 0x000051D9, 0x00003CF6,
    0x0000306D, 0x00050051, 0x0000000B, 0x000049CB, 0x000051D9, 0x00000000,
    0x00060052, 0x00000017, 0x00003CC6, 0x000049CB, 0x00003CAD, 0x00000000,
    0x00050051, 0x0000000B, 0x00004D68, 0x000051D9, 0x00000001, 0x00060052,
    0x00000017, 0x000048EB, 0x00004D68, 0x00003CC6, 0x00000002, 0x0007004F,
    0x00000011, 0x00003FD8, 0x000048EB, 0x000048EB, 0x00000001, 0x00000003,
    0x000500C5, 0x00000011, 0x000022D6, 0x00003FD8, 0x0000062A, 0x00050051,
    0x0000000B, 0x000049CC, 0x000022D6, 0x00000000, 0x00060052, 0x00000017,
    0x00003CC7, 0x000049CC, 0x000048EB, 0x00000001, 0x00050051, 0x0000000B,
    0x00004C5C, 0x000022D6, 0x00000001, 0x00060052, 0x00000017, 0x0000485B,
    0x00004C5C, 0x00003CC7, 0x00000003, 0x00060041, 0x00000294, 0x000023DE,
    0x0000140E, 0x00000A0B, 0x000054A6, 0x0003003E, 0x000023DE, 0x00004028,
    0x00050080, 0x0000000B, 0x00002CC1, 0x000054A6, 0x00000A0D, 0x00060041,
    0x00000294, 0x00005C66, 0x0000140E, 0x00000A0B, 0x00002CC1, 0x0003003E,
    0x00005C66, 0x0000485B, 0x000600A9, 0x0000000B, 0x000041BE, 0x000028E3,
    0x00000A6A, 0x00000A3A, 0x000500C2, 0x0000000B, 0x0000593C, 0x000041BE,
    0x00000A16, 0x00050080, 0x0000000B, 0x0000367B, 0x000053F5, 0x0000593C,
    0x00060041, 0x00000294, 0x0000571A, 0x0000107A, 0x00000A0B, 0x0000367B,
    0x0004003D, 0x00000017, 0x000019B2, 0x0000571A, 0x000300F7, 0x00003A1A,
    0x00000000, 0x000400FA, 0x00005686, 0x00002958, 0x00003A1A, 0x000200F8,
    0x00002958, 0x000500C7, 0x00000017, 0x00004760, 0x000019B2, 0x000009CE,
    0x000500C4, 0x00000017, 0x000024D2, 0x00004760, 0x0000013D, 0x000500C7,
    0x00000017, 0x000050AD, 0x000019B2, 0x0000072E, 0x000500C2, 0x00000017,
    0x0000448E, 0x000050AD, 0x0000013D, 0x000500C5, 0x00000017, 0x00003FF9,
    0x000024D2, 0x0000448E, 0x000200F9, 0x00003A1A, 0x000200F8, 0x00003A1A,
    0x000700F5, 0x00000017, 0x00002AAC, 0x000019B2, 0x00002DA2, 0x00003FF9,
    0x00002958, 0x000300F7, 0x00002DA3, 0x00000000, 0x000400FA, 0x00003B23,
    0x00002B39, 0x00002DA3, 0x000200F8, 0x00002B39, 0x000500C4, 0x00000017,
    0x00005E18, 0x00002AAC, 0x000002ED, 0x000500C2, 0x00000017, 0x00003BE8,
    0x00002AAC, 0x000002ED, 0x000500C5, 0x00000017, 0x000029E9, 0x00005E18,
    0x00003BE8, 0x000200F9, 0x00002DA3, 0x000200F8, 0x00002DA3, 0x000700F5,
    0x00000017, 0x00004505, 0x00002AAC, 0x00003A1A, 0x000029E9, 0x00002B39,
    0x0007004F, 0x00000011, 0x0000594F, 0x00004505, 0x00004505, 0x00000000,
    0x00000001, 0x0009004F, 0x00000017, 0x000029A8, 0x00004505, 0x000000C8,
    0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x000500C2, 0x00000017,
    0x00002582, 0x000029A8, 0x00000203, 0x000500C7, 0x00000017, 0x00001EE6,
    0x00002582, 0x00000603, 0x000500C4, 0x00000017, 0x00006049, 0x00001EE6,
    0x000000B3, 0x000500C2, 0x00000017, 0x00005854, 0x000029A8, 0x00000317,
    0x000500C7, 0x00000017, 0x000053E8, 0x00005854, 0x00000917, 0x000500C5,
    0x00000017, 0x00003CAE, 0x00006049, 0x000053E8, 0x000500C7, 0x00000011,
    0x00004E81, 0x0000594F, 0x00000A7E, 0x000500C4, 0x00000011, 0x00005999,
    0x00004E81, 0x000007F6, 0x000500C7, 0x00000011, 0x000045E5, 0x0000594F,
    0x00000B44, 0x000500C5, 0x00000011, 0x0000306E, 0x00005999, 0x000045E5,
    0x0007004F, 0x00000011, 0x00003CF7, 0x00003CAE, 0x00003CAE, 0x00000000,
    0x00000002, 0x000500C5, 0x00000011, 0x000051DA, 0x00003CF7, 0x0000306E,
    0x00050051, 0x0000000B, 0x000049CD, 0x000051DA, 0x00000000, 0x00060052,
    0x00000017, 0x00003CC8, 0x000049CD, 0x00003CAE, 0x00000000, 0x00050051,
    0x0000000B, 0x00004D69, 0x000051DA, 0x00000001, 0x00060052, 0x00000017,
    0x000048EC, 0x00004D69, 0x00003CC8, 0x00000002, 0x0007004F, 0x00000011,
    0x00003FD9, 0x000048EC, 0x000048EC, 0x00000001, 0x00000003, 0x000500C5,
    0x00000011, 0x000022D7, 0x00003FD9, 0x0000062A, 0x00050051, 0x0000000B,
    0x000049CE, 0x000022D7, 0x00000000, 0x00060052, 0x00000017, 0x00003CC9,
    0x000049CE, 0x000048EC, 0x00000001, 0x00050051, 0x0000000B, 0x00004D6A,
    0x000022D7, 0x00000001, 0x00060052, 0x00000017, 0x00004029, 0x00004D6A,
    0x00003CC9, 0x00000003, 0x0007004F, 0x00000011, 0x00001C34, 0x00004505,
    0x00004505, 0x00000002, 0x00000003, 0x0009004F, 0x00000017, 0x00002C09,
    0x00004505, 0x000000C8, 0x00000002, 0x00000002, 0x00000003, 0x00000003,
    0x000500C2, 0x00000017, 0x00002583, 0x00002C09, 0x00000203, 0x000500C7,
    0x00000017, 0x00001EE7, 0x00002583, 0x00000603, 0x000500C4, 0x00000017,
    0x0000604A, 0x00001EE7, 0x000000B3, 0x000500C2, 0x00000017, 0x00005855,
    0x00002C09, 0x00000317, 0x000500C7, 0x00000017, 0x000053E9, 0x00005855,
    0x00000917, 0x000500C5, 0x00000017, 0x00003CAF, 0x0000604A, 0x000053E9,
    0x000500C7, 0x00000011, 0x00004E82, 0x00001C34, 0x00000A7E, 0x000500C4,
    0x00000011, 0x0000599A, 0x00004E82, 0x000007F6, 0x000500C7, 0x00000011,
    0x000045E6, 0x00001C34, 0x00000B44, 0x000500C5, 0x00000011, 0x0000306F,
    0x0000599A, 0x000045E6, 0x0007004F, 0x00000011, 0x00003CF8, 0x00003CAF,
    0x00003CAF, 0x00000000, 0x00000002, 0x000500C5, 0x00000011, 0x000051DB,
    0x00003CF8, 0x0000306F, 0x00050051, 0x0000000B, 0x000049CF, 0x000051DB,
    0x00000000, 0x00060052, 0x00000017, 0x00003CCA, 0x000049CF, 0x00003CAF,
    0x00000000, 0x00050051, 0x0000000B, 0x00004D6B, 0x000051DB, 0x00000001,
    0x00060052, 0x00000017, 0x000048ED, 0x00004D6B, 0x00003CCA, 0x00000002,
    0x0007004F, 0x00000011, 0x00003FDA, 0x000048ED, 0x000048ED, 0x00000001,
    0x00000003, 0x000500C5, 0x00000011, 0x000022D8, 0x00003FDA, 0x0000062A,
    0x00050051, 0x0000000B, 0x000049D0, 0x000022D8, 0x00000000, 0x00060052,
    0x00000017, 0x00003CCB, 0x000049D0, 0x000048ED, 0x00000001, 0x00050051,
    0x0000000B, 0x00005109, 0x000022D8, 0x00000001, 0x00060052, 0x00000017,
    0x00001E01, 0x00005109, 0x00003CCB, 0x00000003, 0x00050080, 0x0000000B,
    0x0000495D, 0x000054A6, 0x00000A10, 0x00060041, 0x00000294, 0x00001B6C,
    0x0000140E, 0x00000A0B, 0x0000495D, 0x0003003E, 0x00001B6C, 0x00004029,
    0x00050080, 0x0000000B, 0x00002CC2, 0x000054A6, 0x00000A13, 0x00060041,
    0x00000294, 0x00006256, 0x0000140E, 0x00000A0B, 0x00002CC2, 0x0003003E,
    0x00006256, 0x00001E01, 0x000200F9, 0x00004C7A, 0x000200F8, 0x00004C7A,
    0x000100FD, 0x00010038,
};
