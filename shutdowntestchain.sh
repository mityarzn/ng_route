#!/bin/sh

ngctl shutdown route_up:
ngctl shutdown ntee:
ngctl shutdown route_down:
ngctl shutdown ngeth0:
ngctl shutdown 0tee
kldunload ng_route.ko
