#!/bin/sh
#
# chkconfig: 345 85 15
# description: Mojolicious app init.d script

APPNAME=NMAP_API
WORKERS=10
DIRAPP='/home/nmap_api/nmap_api/'
PORT=3000
 
start() {
    echo "Verificando modulos instalados..."
    falhas=0;
    perl -e 'use Data::Printer;'; if (( $? == 0 )); then echo '-> Data::Printer ...OK!'; else echo '-> Data::Printer ...Falhou!';((falhas++)); fi
    perl -e 'use Hash::Merge;'; if (( $? == 0 )); then echo '-> Hash::Merge ...OK!'; else echo '-> Hash::Merge ...Falhou!';((falhas++)); fi
    perl -e 'use Mojo::JSON;'; if (( $? == 0 )); then echo '-> Mojo::JSON ...OK!'; else echo '-> Mojo::JSON ...Falhou!';((falhas++)); fi
    perl -e 'use Mojo::Log;'; if (( $? == 0 )); then echo '-> Mojo::Log ...OK!'; else echo '-> Mojo::Log ...Falhou!';((falhas++)); fi
    perl -e 'use Mojolicious::Lite;'; if (( $? == 0 )); then echo '-> Mojolicious::Lite ...OK!'; else echo '-> Mojolicious::Lite ...Falhou!';((falhas++)); fi
    perl -e 'use MongoDB;'; if (( $? == 0 )); then echo '-> MongoDB ...OK!'; else echo '-> MongoDB ...Falhou!';((falhas++)); fi
    perl -e 'use Nmap::Parser;'; if (( $? == 0 )); then echo '-> NMAP::Parser ...OK!'; else echo '-> NMAP::Parser ...Falhou!';((falhas++)); fi
    perl -e 'use Net::Syslog;'; if (( $? == 0 )); then echo '-> Net::Syslog ...OK!'; else echo '-> Net::Syslog ...Falhou!';((falhas++)); fi
    perl -e 'use NetAddr::IP;'; if (( $? == 0 )); then echo '-> NetAddr::IP ...OK!'; else echo '-> NetAddr::IP ...Falhou!';((falhas++)); fi
    perl -e 'use Readonly;'; if (( $? == 0 )); then echo '-> Readonly ...OK!'; else echo '-> Readonly ...Falhou!';((falhas++)); fi
    perl -e 'use Scalar::Util::Numeric;'; if (( $? == 0 )); then echo '-> Scalar::Util::Numeric ...OK!'; else echo '-> Scalar::Util::Numeric ...Falhou!';((falhas++)); fi
    perl -e 'use XML::Twig;'; if (( $? == 0 )); then echo '-> XML::Twig ...OK!'; else echo '-> XML::Twig ...Falhou!';((falhas++)); fi

    if (( $falhas == 0 )); then echo '-> Modulos do CPAN ...OK!'
       else echo '-> Modulos do CPAN ...Falhou! -> Instale os modulos que falharam!'
       echo '-> Execute para instalar modulos...'
       echo 'cpan install Data::Printer Hash::Merge Mojo::Headers Mojo::JSON Mojo::Log Mojolicious::Lite MongoDB Nmap::Parser Net::Syslog NetAddr::IP Readonly Scalar::Util::Numeric XML::Twig'
       exit
    fi

    echo "Iniciando NMAP::API..."
    cd $DIRAPP
    ./nmap_api.pl prefork -P nmap_api.pid  -w $WORKERS -l http://*:$PORT -w 20 > /dev/null 2> /dev/null &
	if (( $? == 0 )); then echo '-> OK!'; else echo '-> Falhou!'; fi
}
 
stop() {
	echo "Parando servidor web..."
	cd $DIRAPP
	kill -s TERM $(cat nmap_api.pid)
	if (( $? == 0 )); then echo '-> OK!'; else echo '-> Falhou!'; fi
}

case "$1" in
    start)
    start
    ;;
 
    restart)
    stop
    sleep 2
    start
    ;;
 
    stop)
    stop
    ;;

    *)
    echo "usage : $0 start|restart|stop"
    ;;
esac
 
exit 0

