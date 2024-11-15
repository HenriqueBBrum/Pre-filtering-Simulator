find snort3-registered-no-established/ -name '*.rules' -exec sed -i -e 's/,established;/;/g' {} \;
find snort3-registered-no-established/ -name '*.rules' -exec sed -i -e 's/flow:established;//g' {} \;
find snort3-registered-no-established/ -name '*.rules' -exec sed -i -e 's/:established,/:/g' {} \;
find snort3-registered-no-established/ -name '*.rules' -exec sed -i -e 's/,established,/,/g' {} \;