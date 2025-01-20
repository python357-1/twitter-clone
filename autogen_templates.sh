#!/bin/bash
ls ./templates/* | entr -s "templ generate"