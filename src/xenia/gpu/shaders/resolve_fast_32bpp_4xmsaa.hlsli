#include "endian.xesli"
#include "resolve.hlsli"

RWBuffer<uint4> xe_resolve_dest : register(u0);
Buffer<uint4> xe_resolve_source : register(t0);

[numthreads(8, 8, 1)]
void main(uint3 xe_thread_id : SV_DispatchThreadID) {
  // 1 thread = 8 host pixels.
  uint2 pixel_index = xe_thread_id.xy << uint2(3u, 0u);
  // Group height can't cross resolve granularity, Y overflow check not needed.
  [branch] if (pixel_index.x >= XeResolveScaledSize().x) {
    return;
  }
  bool2 duplicate_second = XeResolveDuplicateSecondHostPixel();
  uint source_address_int4s =
      XeEdramOffsetInts(
          uint2(pixel_index.x, max(pixel_index.y, uint(duplicate_second.y))) +
              XeResolveScaledOffset(),
          XeResolveEdramBaseTiles(), XeResolveEdramPitchTiles(),
          kXenosMsaaSamples_4X, XeResolveEdramIsDepth(), 0u,
          XeResolveFirstSampleIndex(), XeResolveResolutionScale())
      >> 2u;
  uint4 pixels_0123, pixels_4567;
  uint sample_select = XeResolveSampleSelect();
  [branch] if (sample_select != kXenosCopySampleSelect_2 &&
               sample_select != kXenosCopySampleSelect_3) {
    pixels_0123.xy = xe_resolve_source[source_address_int4s].xz;
    pixels_0123.zw = xe_resolve_source[source_address_int4s + 1u].xz;
    pixels_4567.xy = xe_resolve_source[source_address_int4s + 2u].xz;
    pixels_4567.zw = xe_resolve_source[source_address_int4s + 3u].xz;
  } else {
    pixels_0123.xy = xe_resolve_source[source_address_int4s].yw;
    pixels_0123.zw = xe_resolve_source[source_address_int4s + 1u].yw;
    pixels_4567.xy = xe_resolve_source[source_address_int4s + 2u].yw;
    pixels_4567.zw = xe_resolve_source[source_address_int4s + 3u].yw;
  }
  if (duplicate_second.x && pixel_index.x == 0u) {
    pixels_0123.x = pixels_0123.y;
  }
  XeResolveSwap8PixelsRedBlue32bpp(pixels_0123, pixels_4567);
  uint endian = XeResolveDestEndian128();
  uint dest_address = XeResolveDestPixelAddress(pixel_index, 2u) >> 4u;
  xe_resolve_dest[dest_address] = XeEndianSwap32(pixels_0123, endian);
  dest_address +=
      XeResolveDestRightConsecutiveBlocksOffset(pixel_index.x, 2u) >> 4u;
  xe_resolve_dest[dest_address] = XeEndianSwap32(pixels_4567, endian);
}
