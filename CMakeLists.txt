cmake_minimum_required(VERSION 2.6)

PROJECT(ulldpd C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations -pedantic)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_EXECUTABLE(ulldpd main.c lldp.c util.c peers.c rx.c tx.c ubus.c config.c)
TARGET_LINK_LIBRARIES(ulldpd ubox blobmsg_json ubus uci)
INSTALL(TARGETS ulldpd
	RUNTIME DESTINATION sbin
)
