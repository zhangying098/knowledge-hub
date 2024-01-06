#!/bin/dash
gcc -Wall -g -o gettextdemo gettextdemo.c
# -k_ 参数表示要提取以下划线 _ 开头的函数调用作为翻译字符串的标识符
xgettext -k_ gettextdemo.c -o ./locale/zh_CN/LC_MESSAGES/dragon.po
xgettext -k_ gettextdemo.c -o ./locale/en_US/LC_MESSAGES/dragon.po

sed -i 's/Content-Type: text\/plain; charset=CHARSET/Content-Type: text\/plain; charset=UTF-8/g' ./locale/zh_CN/LC_MESSAGES/dragon.po
sed -i 's/Content-Type: text\/plain; charset=CHARSET/Content-Type: text\/plain; charset=UTF-8/g' ./locale/en_US/LC_MESSAGES/dragon.po

sed -i 's/msgstr "*"/msgstr "你好世界\\n"/g' ./locale/zh_CN/LC_MESSAGES/dragon.po
sed -i 's/msgstr "*"/msgstr "hello world\\n"/g' ./locale/en_US/LC_MESSAGES/dragon.po

msgfmt -o ./locale/zh_CN/LC_MESSAGES/dragon.mo ./locale/zh_CN/LC_MESSAGES/dragon.po
msgfmt -o ./locale/en_US/LC_MESSAGES/dragon.mo ./locale/en_US/LC_MESSAGES/dragon.po