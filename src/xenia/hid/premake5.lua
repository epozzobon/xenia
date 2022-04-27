project_root = "../../.."
include(project_root.."/tools/build")

group("src")
project("xenia-hid")
  uuid("88a4ef38-c550-430f-8c22-8ded4e4ef601")
  kind("StaticLib")
  language("C++")
  links({
    "xenia-base",
  })
  defines({
  })
  local_platform_files()
  removefiles({"*_demo.cc"})

group("demos")
project("xenia-hid-demo")
  uuid("a56a209c-16d5-4913-85f9-86976fe7fddf")
  kind("WindowedApp")
  language("C++")
  links({
    "fmt",
    "imgui",
    "xenia-base",
    "xenia-helper-sdl",
    "xenia-hid",
    "xenia-hid-nop",
    "xenia-hid-sdl",
    "xenia-ui",
    "xenia-ui-vulkan",
  })
  includedirs({
    project_root.."/third_party/Vulkan-Headers/include",
  })
  files({
    "hid_demo.cc",
    "../ui/windowed_app_main_"..platform_suffix..".cc",
  })
  resincludedirs({
    project_root,
  })

  filter("platforms:Linux")
    links({
      "SDL2",
      "X11",
      "xcb",
      "X11-xcb",
    })

  filter("platforms:Windows")
    links({
      "xenia-hid-winkey",
      "xenia-hid-xinput",
    })
