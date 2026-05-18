ПРОЕКТ АУКЦИОН
открыть 1ый терминал и вписать ЕСЛИ установлен ngrok '''
ngrok http 3000 --request-header-add "ngrok-skip-browser-warning: true"
'''
открыть 2ой терминал и вписать '''
node app.js
'''