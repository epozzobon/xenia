# Copyright 2013 Ben Vanik. All Rights Reserved.
{
  'sources': [
    'gpu-private.h',
    'gpu.cc',
    'gpu.h',
    'graphics_system.cc',
    'graphics_system.h',
    'ring_buffer_worker.cc',
    'ring_buffer_worker.h',
  ],

  'includes': [
    'nop/sources.gypi',
  ],

  'conditions': [
    ['OS == "win"', {
      'includes': [
        #'d3d11/sources.gypi',
      ],
    }],
  ],
}
