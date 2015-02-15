#!/usr/bin/env perl
###############################################################################
#
# API para controle e execucao do NMAP
#
###############################################################################
#
# @ Manoel Domingues Junior mdjunior@ufrj.br
#
###############################################################################

###############################################################################
package Utils;
###############################################################################
use strict;
use warnings;
use Net::Syslog;
use Mojo::Log;
use Readonly;
use Scalar::Util::Numeric qw/isint/;
use Data::Validate::IP qw/is_ipv4 is_ipv6/;

###############################################################################
Readonly my $IPV6_BLOCO_MIN => 128;
Readonly my $IPV6_BLOCO_MAX => 128;
Readonly my $IPV4_BLOCO_MIN => 24;
Readonly my $IPV4_BLOCO_MAX => 32;
Readonly my $PORT_MIN       => 1;
Readonly my $PORT_MAX       => 65_535;
###############################################################################

my %error = (
    '100' => 'Versao invalida!',
    '101' => 'Colecao nao utilizada!',
    '102' => 'Endereco IP invalido!',
    '103' => 'Registro duplicado no banco!',
    '104' => 'Arquivo XML invalido!',
    '105' => 'Ja existem informacoes sobre esse host nesse timestamp!',
    '106' => 'Documento sobre host duplicado no banco!',
    '107' => 'Sem dados sobre host!',
    '108' => 'Host nao possui esse scan associado!',
    '109' => 'Bloco IP invalido!',
    '110' => 'Porta invalida (fora do range permitido)!',
    '111' => 'Porta invalida (nao eh inteiro)!',
    '112' => 'Servico invalido (caracteres nao permitidos)!',
);

#######################################
# Funcao que loga
#######################################
sub log_wrapper {
    my $log = shift;

    if ($ENV{NMAP_API_LOG} eq 'LOCAL') {
        my $log_local = Mojo::Log->new;
        $log_local->info($log);
    }
    elsif ($ENV{NMAP_API_LOG} eq 'NET') {
        my $log_net = Net::Syslog->new(
            Name       => 'NMAP_API',
            Facility   => 'local7',
            Priority   => 'debug',
            SyslogPort => $ENV{NMAP_API_SYSLOG_PORT},
            SyslogHost => $ENV{NMAP_API_SYSLOG_HOST},
        );
        $log_net->send($log, Priority => 'info');
    }
    return;
}

#######################################
# Funcao que retorna os erros
#######################################
sub error {
    my $code = shift;
    my $info = shift;

    if (!defined $info) { $info = q{}; }

    Utils::log_wrapper("code=|$code| desc=|$error{$code}| info=|$info|");

    my %hash = (result => 'error', code => $code, message => $error{$code},);
    return \%hash;
}

sub valida_bloco {
    my $net  = shift;
    my $mask = shift;

    if (!defined $mask) {
        if (is_ipv4($net)) {
            $mask = $IPV4_BLOCO_MAX;
        }
        elsif (is_ipv6($net)) {
            $mask = $IPV6_BLOCO_MAX;
        }
    }

    if (is_ipv4($net)) {
        if ($mask > $IPV4_BLOCO_MAX || $mask < $IPV4_BLOCO_MIN) {
            return Utils::error('109', "NET:$net MASK:$mask");
        }
    }
    elsif (is_ipv6($net)) {
        if ($mask > $IPV6_BLOCO_MAX || $mask < $IPV6_BLOCO_MIN) {
            return Utils::error('109', "NET:$net MASK:$mask");
        }
    }
    my %hash = (result => 'success',);
    return \%hash;
}

sub valida_port {
    my $port = shift;
    if ($port < $PORT_MIN && $port > $PORT_MAX) {
        return Utils::error('110', "PORT: $port");
    }
    elsif (!isint($port)) {
        return Utils::error('111', "PORT: $port");
    }
    my %hash = (result => 'success',);
    return \%hash;
}

sub valida_service {
    my $service = shift;
    if ($service !~ /[\w?-]+/smx) {
        return Utils::error('112', "SERVICE: $service");
    }
    my %hash = (result => 'success',);
    return \%hash;
}

###############################################################################
package Model;
###############################################################################
use strict;
use warnings;
use XML::Twig;
use Nmap::Parser;
use MongoDB;
use Mojo::JSON qw(j);
use Hash::Merge qw( merge );
use NetAddr::IP;

my $client = MongoDB::MongoClient->new(
    host => $ENV{NMAP_API_MONGO_HOST},
    port => $ENV{NMAP_API_MONGO_PORT}
);
my $db = $client->get_database($ENV{NMAP_API_DATABASE});

#######################################
# Funcao que conta a quantidade atuais de documentos em uma colecao
#######################################
sub count {
    my $collection = shift;
    my $count      = $db->get_collection($collection)->count;
    my %hash       = (result => 'success', total => $count,);
    return \%hash;
}

#######################################
# Funcao que retorna os hosts cadastrados
#######################################
sub get_hosts {
    my $hosts = $db->run_command(
        [
            distinct => $ENV{NMAP_API_HOST_COLLECTION},
            key      => 'addr',
            query    => {}
        ]
    );

    return $hosts->{values};
}

#######################################
# Funcao que retorna os scans cadastrados
#######################################
sub get_scans {
    my $scans = $db->run_command(
        [
            distinct => $ENV{NMAP_API_SCAN_COLLECTION},
            key      => 'timestamp',
            query    => {}
        ]
    );

    return $scans->{values};
}

#######################################
# Funcao que retorna informacoes sobre um host
#######################################
sub get_host_info {
    my $addr        = shift;
    my $scan_number = shift;
    my $port        = shift;
    my $service     = shift;

    my $hosts = $db->get_collection($ENV{NMAP_API_HOST_COLLECTION})
        ->find({addr => $addr});
    my $num = $hosts->count;
    if ($num > 1) {
        return Utils::error('103', "IP:$addr HOSTS_NUM:$num");
    }
    elsif ($num < 1) {
        return Utils::error('107', "IP:$addr HOSTS_NUM:$num");
    }
    my $doc = $hosts->next;    # Guarda informacoes sobre host

    my $scans;

    # verifica se exixte numero de scan associado
    if (defined $scan_number) {
        Utils::log_wrapper(
            "function=|get_host_info| action=|using_parameter_scan| desc=|| info=|$scan_number|"
        );
    }
    else {
        # Obtendo dados mais recentes de varredura
        my @array_scans = reverse sort { $a <=> $b } @{$doc->{scans}};
        $scan_number = $array_scans[0];    # Guarda scan mais recentes
    }

    if (defined $port && defined $service) {
        Utils::log_wrapper(
            "function=|get_host_info| action=|using_parameters_port_service| desc=|| info=|PORT:$port SERVICE:$service|"
        );
        $scans = $db->get_collection($ENV{NMAP_API_SCAN_COLLECTION})->find(
            {
                timestamp            => "$scan_number",
                'hosts.addr'         => $addr,
                'hosts.data.port'    => "$port",
                'hosts.data.service' => "$service"
            }
        );
    }
    elsif (defined $port) {
        Utils::log_wrapper(
            "function=|get_host_info| action=|using_parameter_port| desc=|| info=|PORT:$port|"
        );
        $scans = $db->get_collection($ENV{NMAP_API_SCAN_COLLECTION})->find(
            {
                timestamp         => "$scan_number",
                'hosts.addr'      => $addr,
                'hosts.data.port' => "$port"
            }
        );
    }
    elsif (defined $service) {
        Utils::log_wrapper(
            "function=|get_host_info| action=|using_parameter_service| desc=|| info=|SERVICE:$service|"
        );
        $scans = $db->get_collection($ENV{NMAP_API_SCAN_COLLECTION})->find(
            {
                timestamp            => "$scan_number",
                'hosts.addr'         => $addr,
                'hosts.data.service' => "$service"
            }
        );
    }
    else {
        Utils::log_wrapper(
            'function=|get_host_info| action=|no_using_parameter| desc=|| info=||');
        $scans = $db->get_collection($ENV{NMAP_API_SCAN_COLLECTION})
            ->find({timestamp => "$scan_number", 'hosts.addr' => $addr});
    }

    my $scan_count = $scans->count;
    if ($scan_count != 1) {
        return Utils::error('108', "IP:$addr SCAN:$scan_number");
    }
    my $scan      = $scans->next;
    my $scan_info = $scan->{hosts}[0];

    # Fazendo merge dos hashs
    my %scans_ = (scans => $doc->{scans},);
    my %all_info = %{merge($scan_info, \%scans_)};

    return \%all_info;
}

#######################################
# Funcao que retorna informacoes sobre uma rede
#######################################
sub net {
    my ($net, $mask, $port, $service) = @_;

    my %net_info;    # Hash para guardar as informações da rede
    my $SLASH = q{/};
    my $n     = NetAddr::IP->new($net . $SLASH . $mask);

    Utils::log_wrapper(
        "function=|net| action=|list| desc=|| info=|$net $mask|");
    my $bits = $n->bits();
    for my $ip (@{$n->splitref($bits)}) {    # laco com cada IP da rede
        my $host_hash = host($ip->addr, undef, $port, $service);
        if (!defined $host_hash->{result}) {
            $net_info{$ip->addr} = $host_hash;
        }
    }

    # verificando numero de resultados
    my $hash_size = scalar keys %net_info;
    Utils::log_wrapper(
        "function=|net| action=|result| desc=|| info=|$hash_size|");

    return \%net_info;
}

#######################################
# Funcao que gera as estruturas para importacao de dados
#	Atencao: Essa funcao chama outras para armazenar as estruturas no banco
#######################################
sub import {
    my $xml = shift;

    # Validando XML
    my $twig = XML::Twig->new();
    my $res  = $twig->safe_parse($xml);
    if (!defined $res) {
        $twig->purge;
        return Utils::error('104', $xml);
    }
    $twig->purge;

    # Parseando com o NMAP
    my $nmap = Nmap::Parser->new();
    $nmap->parse($xml);

    # Informacoes do SCAN
    my $session      = $nmap->get_session();
    my %session_info = (
        timestamp    => $session->start_time(),
        finish_time  => $session->finish_time(),
        scan_version => $session->nmap_version(),
        num_services => $session->numservices(),
        scan_types   => $session->scan_types(),
    );

    # Para cada host
    my @hosts;
    for my $host ($nmap->all_hosts()) {
        my $os = $host->os_sig;

        my @hostnames = $host->all_hostnames();
        my @services;

        # TCP
        for my $svcs ($host->tcp_open_ports()) {
            my $svc = $host->tcp_service($svcs);
            my %additional_info;
            for my $nse_script_name ($svc->scripts()) {

                # Sanitizando nome que nao pode conter pontos
                my $new_script_name = $nse_script_name;
                $new_script_name =~ s/[.]/_/smxg;
                $additional_info{$new_script_name}
                    = $svc->scripts($nse_script_name);
            }
            my %service_info = (
                service         => $svc->name(),
                proto           => 'tcp',
                port            => $svc->port(),
                product         => $svc->product(),
                fingerprint     => $svc->fingerprint(),
                version         => $svc->version(),
                rpc             => $svc->rpcnum(),
                additional_info => \%additional_info,
            );
            push @services, \%service_info;
        }

        # UDP
        for my $svcs ($host->udp_open_ports()) {
            my $svc = $host->udp_service($svcs);
            my %additional_info;
            for my $nse_script_name ($svc->scripts()) {

                # Sanitizando nome que nao pode conter pontos
                my $new_script_name = $nse_script_name;
                $new_script_name =~ s/[.]/_/smxg;
                $additional_info{$new_script_name}
                    = $svc->scripts($nse_script_name);
            }
            my %service_info = (
                service         => $svc->name(),
                proto           => 'udp',
                port            => $svc->port(),
                product         => $svc->product(),
                fingerprint     => $svc->fingerprint(),
                version         => $svc->version(),
                rpc             => $svc->rpcnum(),
                additional_info => \%additional_info,
            );
            push @services, \%service_info;
        }

        # Informacoes agregadas
        my %host_info = (
            hostnames  => \@hostnames,
            status     => $host->status(),
            addr       => $host->addr(),
            os         => $os->name(),
            os_family  => $os->osfamily(),
            status     => $host->status(),
            mac_addr   => $host->mac_addr(),
            distance   => $host->distance(),
            mac_vendor => $host->mac_vendor(),
            uptime     => $host->uptime_seconds(),
            data       => \@services,
        );
        push @hosts, \%host_info;

        # Atualizando colecao de hosts
        my %update_info = (
            addr           => $host_info{addr},
            scan_timestamp => $session_info{timestamp},
            status         => $host_info{status},
            os             => $os->name(),
            hostnames      => \@hostnames,
        );
        my $result = add_scan_in_host(\%update_info);
        Utils::log_wrapper(
            "function=|import| action=|add_scan_in_host| desc=|adicionando scan a host| info=|IP:$host_info{addr} RESULT:$result->{result}|"
        );

    }

    # Atualizando colecao de scans
    $session_info{hosts} = \@hosts;    # Guarda na collection scans
    my $result = add_scan(\%session_info);
    Utils::log_wrapper(
        "function=|import| action=|add_scan| desc=|adicionando scan a colecao| info=|TIMESTAMP:$session_info{timestamp} RESULT:$result->{result}|"
    );
    return $result;
}

#######################################
#  Funcao que recebe os dados de um scan e armazena no banco
#######################################
sub add_scan {
    my $scan_info = shift;
    my $scan_str  = j($scan_info);
    $scan_str =~ s/\n//smxg;
    Utils::log_wrapper(
        "function=|add_scan| action=|add_scan| desc=|adicionando scan a colecao| info=|$scan_str|"
    );

    my $scan = $db->get_collection($ENV{NMAP_API_SCAN_COLLECTION});
    $scan->insert($scan_info);
    my %result = (result => 'success',);
    return \%result;
}

#######################################
#  Funcao que recebe os dados de um host e armazena no banco
#######################################

#######################################
sub add_scan_in_host {
    my $update_info = shift;

    #   Estrutura do update_info
    #	%update_info = (
    #		addr => $,
    #		scan_timestamp => $,
    #		status => $,
    #		os => $,
    #		hostnames => \@,
    #		);

    # Verificando se ja existe registro do host
    my $hosts = $db->get_collection($ENV{NMAP_API_HOST_COLLECTION})
        ->find({addr => $update_info->{addr}});
    my $num = $hosts->count;

    if ($num == 0) {
        MongoDB::force_int($update_info->{scan_timestamp});
        my %hash = (
            addr      => $update_info->{addr},
            status    => $update_info->{status},
            os        => $update_info->{os},
            hostnames => $update_info->{hostnames},
            scans     => [$update_info->{scan_timestamp}],
        );
        my $host = $db->get_collection($ENV{NMAP_API_HOST_COLLECTION});
        Utils::log_wrapper(
            "function=|add_scan_in_host| action=|add_host| desc=|adicionando host| info=|IP:$update_info->{addr}|"
        );
        $host->insert(\%hash);
        my %result = (result => 'success',);
        return \%result;
    }
    elsif ($num == 1) {
        my $doc = $hosts->next;
        my @array_scans = reverse sort { $a <=> $b } @{$doc->{scans}};

        if ($array_scans[0] < $update_info->{scan_timestamp})
        {    # Se o scan eh mais atual que os existentes
            my @scans = @array_scans;
            push @scans, scalar $update_info->{scan_timestamp};

            my %hash = (
                addr      => $update_info->{addr},
                status    => $update_info->{status},
                os        => $update_info->{os},
                hostnames => $update_info->{hostnames},
                scans     => \@scans,
            );
            my $host = $db->get_collection($ENV{NMAP_API_HOST_COLLECTION});
            Utils::log_wrapper(
                "function=|add_scan_in_host| action=|update_host_all| desc=|atualizando host| info=|IP:$update_info->{addr}|"
            );
            $host->update({'addr' => $update_info->{addr}},
                {'$set' => \%hash});
            my %result = (result => 'success',);
            return \%result;
        }
        elsif ($array_scans[0] > $update_info->{scan_timestamp})
        {    # Se o scan eh mais antigo que os existentes
            my $host = $db->get_collection($ENV{NMAP_API_HOST_COLLECTION});
            Utils::log_wrapper(
                "function=|add_scan_in_host| action=|update_host_scan_info| desc=|atualizando informacao de scan| info=|IP:$update_info->{addr}|"
            );
            $host->update({'addr' => $doc->{addr}},
                {'$push' => {'scans' => $update_info->{scan_timestamp}}});
            my %result = (result => 'success',);
            return \%result;
        }
        else {    # Se ja existe um scan com mesmo timestamp entre existentes
            return Utils::error('105',
                "IP:$update_info->{addr} TIMESTAMP:$update_info->{scan_timestamp}"
            );
        }
    }
    else {
        return Utils::error('106', "IP:$update_info->{addr} HOSTS_NUM:$num");
    }
}

###############################################################################
package Main;
###############################################################################

use strict;
use warnings;
use Mojolicious::Lite;
use Mojo::JSON;
use Mojo::Headers;
our $VERSION = 1.0;

get '/api/#version/:collection/count' => sub {
    my $self = shift;
    if ($self->param('version') != $VERSION) {
        $self->render(json => Utils::error('100', $self->param('version')));
        return;
    }
    if (   $self->param('collection') ne $ENV{NMAP_API_HOST_COLLECTION}
        && $self->param('collection') ne $ENV{NMAP_API_SCAN_COLLECTION})
    {
        $self->render(json => Utils::error('101', $self->param('collection')));
        return;
    }
    $self->render(json => Model::count($self->param('collection')));
};

get '/api/#version/hosts' => sub {
    my $self = shift;

    $self->render(json => Model::get_hosts());
    return;
};

get '/api/#version/hosts/#addr' => sub {
    my $self = shift;

    if ($self->param('version') != $VERSION) {
        $self->render(json => Utils::error('100', $self->param('version')));
        return;
    }
    my $validacao = Utils::valida_bloco($self->param('addr'));
    if ($validacao->{result} ne 'success') {
        $self->render(json => $validacao);
        return;
    }
    if (defined $self->param('scan')) {
        $self->render(
            json => Model::get_host_info($self->param('addr'), $self->param('scan')));
        return;
    }
    $self->render(json => Model::get_host_info($self->param('addr')));
};

get '/api/#version/net/#addr/:mask' => sub {
    my $self = shift;

    my $port    = $self->param('port');
    my $service = $self->param('service');

    if ($self->param('version') != $VERSION) {
        $self->render(json => Utils::error('100', $self->param('version')));
        return;
    }
    my $validacao
        = Utils::valida_bloco($self->param('addr'), $self->param('mask'));
    if ($validacao->{result} ne 'success') {
        $self->render(json => $validacao);
        return;
    }
    if (defined $self->param('port')) {
        my $validacao_port = Utils::valida_port($self->param('port'));
        if ($validacao_port->{result} ne 'success') {
            $self->render(json => $validacao_port);
            return;
        }
    }
    else { $port = undef; }

    if (defined $self->param('service')) {
        my $validacao_service = Utils::valida_service($self->param('service'));
        if ($validacao_service->{result} ne 'success') {
            $self->render(json => $validacao_service);
            return;
        }
    }
    else { $service = undef; }

    $self->render(
        json => Model::net(
            $self->param('addr'),
            $self->param('mask'),
            $port, $service
        )
    );
};

get '/api/#version/scans' => sub {
    my $self = shift;

    $self->render(json => Model::get_scans());
    return;
};

put '/api/#version/scans' => sub {
    my $self = shift;
    if ($self->param('version') != $VERSION) {
        $self->render(json => Utils::error('100', $self->param('version')));
        return;
    }
    $self->render(json => Model::import($self->req->body), status => 201);
};

app->config(
    hypnotoad => {
        listen    => ["$ENV{NMAP_API_URL}"],
        workers   => $ENV{NMAP_API_WORKERS},
        clients   => 1,                        # is a blocking API
        lock_file => 'run/nmap_api.lock',
        pid_file  => 'run/nmap_api.pid',
        user      => $ENV{NMAP_API_USER},
        group     => $ENV{NMAP_API_GROUP},
    }
);

app->start;
__DATA__
@@ exception.html.ep
{"result": "error"}

@@ not_found.html.ep
{"result": "error"}
