find snort3-registered-no-established/ -name '*.rules' -exec sed -i -e 's/,established;/,stateless;/g' {} \;
find snort3-registered-no-established/ -name '*.rules' -exec sed -i -e 's/flow:established;/flow:stateless;/g' {} \;
find snort3-registered-no-established/ -name '*.rules' -exec sed -i -e 's/:established,/:stateless,/g' {} \;
find snort3-registered-no-established/ -name '*.rules' -exec sed -i -e 's/,established,/,stateless,/g' {} \;