cmake_minimum_required(VERSION 3.10)
project(SetSail C)

set(CMAKE_C_STANDARD 99)
if(NOT MSVC)
	add_compile_options(-Wall -Wextra)
endif()

include(ProductVersion.cmake)
generate_product_version(
	SETSAIL_RC
	NAME "Launcher"
	BUNDLE "SetSail Launchers"
	VERSION_MAJOR 1
	VERSION_MINOR 0
	COMPANY_NAME "Assembly Armada"
	COMPANY_COPYRIGHT "Code released under GPLv2 or later."
	ORIGINAL_FILENAME "setsaillauncher.exe"
	ICON "${CMAKE_CURRENT_SOURCE_DIR}/launcher.ico"
)

add_executable(launcher launcher.c ${SETSAIL_RC})
add_library(loader SHARED loader.c)
