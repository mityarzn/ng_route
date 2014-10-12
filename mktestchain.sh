#!/bin/sh

#kldload ./ng_route.ko
ngctl mkpeer em1: route lower down
ngctl name em1:lower route_up
ngctl mkpeer route_up: tee notmatch left
ngctl name route_up:notmatch ntee
ngctl mkpeer ntee: route right notmatch
ngctl name ntee:right route_down
ngctl mkpeer route_down: eiface down ether

ngctl mkpeer route_up: tee up0 left
ngctl name route_up:up0 0tee
ngctl connect route_down: 0tee: up0 right

ifconfig ngeth0 ether 08:00:27:4e:0c:ae
ifconfig ngeth0 192.168.11.1/24 up