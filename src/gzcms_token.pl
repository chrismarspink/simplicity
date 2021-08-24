# Copyright 2020-2022 GZCMS/SmartCity Projects by Jinkyu Kim. All Rights Reserved.
use strict;
use warnings;
use Term::ANSIColor;

my $openssl = "openssl";
my $verbose = 0;

my $OPENSSL_CONFIG = "./openssl.cnf" || "";
my $DAYS = "-days 365";
my $CADAYS = "-days 1095";	# 3 years
my $REQ = "$openssl req -config $OPENSSL_CONFIG";
my $CA = "$openssl ca -config $OPENSSL_CONFIG";
my $VERIFY = "$openssl verify";
my $X509 = "$openssl x509";
my $PKCS12 = "$openssl pkcs12";
my $ECPARAM = "$openssl ecparam";

# default openssl.cnf file has setup as per the following
my $CATOP = "./token/rootca";
my $CAKEY = "ca.key";
my $CAPARAM = "ca.param";
my $CAREQ = "ca.req";
my $CACERT = "ca.pem";
my $CACRL = "crl.pem";
my $DIRMODE = 0777;

my $NEWKEY = "new.key";
my $NEWREQ = "new.req";
my $NEWCERT = "newcert.pem";
my $NEWP12 = "newcert.p12";

my $REQ_PEM_F = "new.req";
my $REQ_KEY_F = "new.key";
my $REQ_PARAM_F = "new.param";

my $certfile = "";
my $keyfile = "";

my $RET = 0;
my $WHAT = shift @ARGV || "";
my @OPENSSL_CMDS = ("req", "ca", "pkcs12", "x509", "verify");
my %EXTRA = extra_args(\@ARGV, "-extra-");
my $FILE;

sub extra_args {
    my ($args_ref, $arg_prefix) = @_;
    my %eargs = map {
	if ($_ < $#$args_ref) {
	    my ($arg, $value) = splice(@$args_ref, $_, 2);
	    $arg =~ s/$arg_prefix//;
	    ($arg, $value);
	} else {
	    ();
	}
    } reverse grep($$args_ref[$_] =~ /$arg_prefix/, 0..$#$args_ref);
    my %empty = map { ($_, "") } @OPENSSL_CMDS;
    return (%empty, %eargs);
}

# See if reason for a CRL entry is valid; exit if not.
sub crl_reason_ok 
{
    my $r = shift;

    if ($r eq 'unspecified' || $r eq 'keyCompromise'
        || $r eq 'CACompromise' || $r eq 'affiliationChanged'
        || $r eq 'superseded' || $r eq 'cessationOfOperation'
        || $r eq 'certificateHold' || $r eq 'removeFromCRL') {
        return 1;
    }
    print STDERR "Invalid CRL reason; must be one of:\n";
    print STDERR "    unspecified, keyCompromise, CACompromise,\n";
    print STDERR "    affiliationChanged, superseded, cessationOfOperation\n";
    print STDERR "    certificateHold, removeFromCRL";
    exit 1;
}

# Copy a PEM-format file; return like exit status (zero means ok)
sub copy_pemfile
{
    my ($infile, $outfile, $bound) = @_;
    my $found = 0;

    open IN, $infile || die "Cannot open $infile, $!";
    open OUT, ">$outfile" || die "Cannot write to $outfile, $!";
    while (<IN>) {
        $found = 1 if /^-----BEGIN.*$bound/;
        print OUT $_ if $found;
        $found = 2, last if /^-----END.*$bound/;
    }
    close IN;
    close OUT;
    return $found == 2 ? 0 : 1;
}

# Wrapper around system; useful for debugging.  Returns just the exit status
sub run
{
    my $cmd = shift;
    print "====\n$cmd\n" if $verbose;
    my $status = system($cmd);
    print "==> $status\n====\n" if $verbose;
    return $status >> 8;
}


if ( $WHAT =~ /^(-\?|-h|-help)$/ ) {
    print STDERR colored("USAGE: \n", 'bold yellow');
    ;
    print STDERR "       gzcms_token.pl -newca | -crl\n";
    print STDERR "       gzcms_token.pl -newreq name\n";
    print STDERR "       gzcms_token.pl -sign name\n";
    print STDERR "       gzcms_token.pl -add {device|server|ca} {ID}\n";
    #print STDERR "usage: gzcms_token.pl -newcert | -newreq | -newreq-nodes | -xsign | -sign | -signCA | -signcert | -crl | -newca [-extra-cmd extra-params]\n";
    print STDERR "       gzcms_token.pl -pkcs12 [-extra-pkcs12 extra-params] [certname]\n";
    print STDERR "       gzcms_token.pl -revoke [-extra-ca extra-params] certfile [reason]\n";
    print STDERR "\n";
    print STDERR colored("Valid CRL reason; must be one of:\n", 'bold yellow');
    print STDERR "        unspecified, keyCompromise, CACompromise,\n";
    print STDERR "        affiliationChanged, superseded, cessationOfOperation\n";
    print STDERR "        certificateHold, removeFromCRL\n\n";
    exit 0;
}
if ($WHAT eq '-newcert' ) {
    # create a certificate
    $RET = run("$REQ -new -x509 -keyout $NEWKEY -out $NEWCERT $DAYS $EXTRA{req}");
    print "Cert is in $NEWCERT, private key is in $NEWKEY\n" if $RET == 0;
} elsif ($WHAT eq '-precert' ) {
    # create a pre-certificate
    $RET = run("$REQ -x509 -precert -keyout $NEWKEY -out $NEWCERT $DAYS");
    print "Pre-cert is in $NEWCERT, private key is in $NEWKEY\n" if $RET == 0;
} elsif ($WHAT =~ /^\-newr_OLD_eq(\-nodes)?$/ ) {
    # create a certificate request
    $RET = run("$REQ -new $1 -keyout $NEWKEY -out $NEWREQ $DAYS $EXTRA{req}");
    print "Request is in $NEWREQ, private key is in $NEWKEY\n" if $RET == 0;
} elsif ($WHAT eq '-newreq' ) {
    my $fn = $ARGV[0];
    
    if ($fn ne "") {
        $REQ_PEM_F = "$fn" . ".req";
        $REQ_KEY_F = "$fn" . ".key";
        $REQ_PARAM_F = "$fn" . ".param";
    } else {
        $REQ_PEM_F = "new.req";
        $REQ_KEY_F = "new.key";
        $REQ_PARAM_F = "new.param";
    }

    print "Making Certificate Signing Request ...\n";

    $RET = run("$ECPARAM -name secp256k1 -out ${CATOP}/reqs/$REQ_PARAM_F");
    $RET = run("$REQ -new -newkey ec:${CATOP}/reqs/$REQ_PARAM_F -keyout ${CATOP}/reqs/$REQ_KEY_F -out ${CATOP}/reqs/$REQ_PEM_F");
    
    print "REQUEST, csr=$[REQ_PEM_F], key=[$REQ_KEY_F], param=[$REQ_PARAM_F], generated.\n";

} elsif ($WHAT eq '-newca' ) {
    # create the directory hierarchy
    mkdir ${CATOP}, $DIRMODE;
    mkdir "${CATOP}/certs", $DIRMODE;
    mkdir "${CATOP}/crl", $DIRMODE ;
    mkdir "${CATOP}/newcerts", $DIRMODE;
    mkdir "${CATOP}/private", $DIRMODE;
    mkdir "${CATOP}/reqs", $DIRMODE;
    open OUT, ">${CATOP}/index.txt";
    close OUT;
    open OUT, ">${CATOP}/crlnumber";
    print OUT "01\n";
    close OUT;
    # ask user for existing CA certificate
    print "CA certificate filename (or enter to create)\n";
    $FILE = "" unless defined($FILE = <STDIN>);
    $FILE =~ s{\R$}{};
    if ($FILE ne "") {
        copy_pemfile($FILE,"${CATOP}/private/$CAKEY", "PRIVATE");
        copy_pemfile($FILE,"${CATOP}/$CACERT", "CERTIFICATE");
    } else {
        print "Making CA certificate ...\n";

        $RET = run("$ECPARAM -name secp521r1 -out ${CATOP}/private/$CAPARAM");

        $RET = run("$REQ -new -newkey ec:${CATOP}/private/$CAPARAM -keyout ${CATOP}/private/$CAKEY -out ${CATOP}/$CAREQ $EXTRA{req}");

        $RET = run("$CA -create_serial"
                . " -out ${CATOP}/$CACERT $CADAYS -batch"
                . " -keyfile ${CATOP}/private/$CAKEY -selfsign"
                . " -extensions v3_ca $EXTRA{ca}"
                . " -infiles ${CATOP}/$CAREQ") if $RET == 0;
        print "CA certificate is in ${CATOP}/$CACERT\n" if $RET == 0;
    }
} elsif ($WHAT eq '-pkcs12' ) {
    my $cname = $ARGV[0];
    $cname = "My Certificate" unless defined $cname;
    $RET = run("$PKCS12 -in $NEWCERT -inkey $NEWKEY"
            . " -certfile ${CATOP}/$CACERT"
            . " -out $NEWP12"
            . " -export -name \"$cname\" $EXTRA{pkcs12}");
    print "PKCS #12 file is in $NEWP12\n" if $RET == 0;
} elsif ($WHAT eq '-xsign' ) {
    $RET = run("$CA -policy policy_anything $EXTRA{ca} -infiles $NEWREQ");
} elsif ($WHAT eq '-sign' ) {
    my $name = $ARGV[0];
    $name = "new" unless defined $name;
    print "Request name: $name\n";
    if ($name) {
        print "Making Certificate : $name ...\n";
        $REQ_PEM_F = "$name" . ".req";
        $REQ_KEY_F = "$name" . ".key";
        $REQ_PARAM_F = "$name" . ".param";
        $NEWCERT = "$name" . ".pem";
        $RET = run("$CA -out ${CATOP}/reqs/$NEWCERT $EXTRA{ca} -infiles ${CATOP}/reqs/$REQ_PEM_F");
    } else {
        print "Making Certificate : new ...\n";
        $REQ_PEM_F = "new.req";
        $REQ_KEY_F = "new.key";
        $REQ_PARAM_F = "new.param";
        $RET = run("$CA -out $NEWCERT $EXTRA{ca} -infiles  $NEWREQ");
    } 
    print "Signed certificate is in $NEWCERT\n" if $RET == 0;

} elsif ($WHAT eq '-gentoken' ) {
    my $to = $ARGV[0];
    my $id = $ARGV[1];

    #새로운 token 구조를 생성
    if ($to eq 'new' ) {
        my $TOKEN_NAME = "./token/";
        my $TOKENTOP = $TOKEN_NAME . $id;
        mkdir ${TOKENTOP}, $DIRMODE;
        mkdir "${TOKENTOP}/bin", $DIRMODE;
        mkdir "${TOKENTOP}/cert", $DIRMODE ;
        mkdir "${TOKENTOP}/cert/device", $DIRMODE ;
        mkdir "${TOKENTOP}/cert/server", $DIRMODE ;
        mkdir "${TOKENTOP}/cert/ca", $DIRMODE ;
        mkdir "${TOKENTOP}/include", $DIRMODE;
        mkdir "${TOKENTOP}/lib", $DIRMODE;
        mkdir "${TOKENTOP}/docs", $DIRMODE;
        exit 1;
    } 
     
    if ($to eq 'ca' ) {
        $certfile = "./token/rootca/ca.pem";
        $keyfile = "./token/rootca/private/ca.key";
    } else {
        $certfile = "./token/rootca/reqs/" . $id . ".pem";
        $keyfile = "./token/rootca/reqs/" . $id . ".key";
    }

    print STDERR "Add certificate/key from [" . colored($id, 'bold yellow') . "] to [" . colored($to, 'bold yellow') .  "]\n";
    
    my $targetdir = "./token/gzcms/cert/" . $to . "/";
    if ($to eq 'device' ||  $to eq 'ca' ) {
        $RET = run("cp $keyfile $targetdir");
        print STDERR "copy " . colored($keyfile, 'bold red') . " to " . colored($targetdir, 'bold yellow') . "\n";
    }
    $RET = run("cp $certfile $targetdir");
    print STDERR "copy " . colored($certfile, 'bold yellow') . " to " . colored($targetdir, 'bold yellow') . "\n";

    print STDERR "Add certificate/key from [ " . colored($certfile, 'bold yellow') . "] to [" . colored($targetdir, 'bold yellow') . "]\n";

} elsif ($WHAT eq '-signCA' ) {
    $RET = run("$CA -policy policy_anything -out $NEWCERT"
            . " -extensions v3_ca $EXTRA{ca} -infiles $NEWREQ");
    print "Signed CA certificate is in $NEWCERT\n" if $RET == 0;
} elsif ($WHAT eq '-signcert' ) {
    $RET = run("$X509 -x509toreq -in $NEWREQ -signkey $NEWREQ -out tmp.pem $EXTRA{x509}");
    $RET = run("$CA -policy policy_anything -out $NEWCERT $EXTRA{ca} -infiles tmp.pem") if $RET == 0;
    print "Signed certificate is in $NEWCERT\n" if $RET == 0;
} elsif ($WHAT eq '-verify' ) {
    my @files = @ARGV ? @ARGV : ( $NEWCERT );
    my $file;
    foreach $file (@files) {
        my $status = run("$VERIFY \"-CAfile\" ${CATOP}/$CACERT $file $EXTRA{verify}");
        $RET = $status if $status != 0;
    }
} elsif ($WHAT eq '-crl' ) {
    $RET = run("$CA -gencrl -out ${CATOP}/crl/$CACRL $EXTRA{ca}");
    print "Generated CRL is in ${CATOP}/crl/$CACRL\n" if $RET == 0;
} elsif ($WHAT eq '-revoke' ) {
    my $cname = $ARGV[0];
    if (!defined $cname) {
        print "Certificate filename is required; reason optional.\n";
        exit 1;
    }
    my $reason = $ARGV[1];
    $reason = " -crl_reason $reason"
        if defined $reason && crl_reason_ok($reason);
    $RET = run("$CA -revoke \"$cname\"" . $reason . $EXTRA{ca});
} else {
    print STDERR "Unknown arg \"$WHAT\"\n";
    print STDERR "Use -help for help.\n";
    exit 1;
}

exit $RET;
