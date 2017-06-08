echo 'Install VAIS'
echo ' > set command'
MYPWD=`pwd`
echo '#/usr/bin/ruby
ruby '$MYPWD'/vais.rb $*' >> /usr/bin/vais
echo ' > set perm'
chmod 755 /usr/bin/vais
echo 'Finhish'

