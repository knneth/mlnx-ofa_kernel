#!/bin/bash

#This line join lines broken by a final '\', otherwise unifdef doesn't know how to handle.
sed -e  ':x /\\$/ { N; s/\\\n//g ; bx }' -e '1,4d'
