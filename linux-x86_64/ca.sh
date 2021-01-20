#!/bin/bash

DIALOG_CANCEL=1
DIALOG_ESC=255
HEIGHT=0
WIDTH=0

GZPKI-CLI=../linux-x86_64/gzpki-cli

display_result() {
    dialog --title $1 --no-collapse --msgbox "$result" 0 0
}

while true; do 
    exec 3>&1
    selection=$(dialog --backtitle "GZCMM CA" \
        --title "Select" \
        --clear \
        --cancel-label "Exit" \
        --menu "Please select: " $HEIGHT $WIDTH 4 \
        "1" "View CSR" \
        "2" "View Certificate" \
        "3" "View CRL" \
        "4" "Import CSR file" \
        "5" "Issue Certificate" \
        "6" "Issue CRL" \
        "7" "View Keypass" \
        2>&1 1>&3)
    exit_status=$?
    exec 3>&-
    case $exit_status in 
        $DIALOG_CANCEL)
            clear
            echo "Program terminated"
            exit
            ;;
        $DIALOG_ESC)
            clear 
            echo "Program aborted" >&2
            exit 1
            ;;
    esac

    case $selection in
        0 )
            clear
            echo "Program terminated"
            ;;
        1 ) 
            result=$(./gzpki-cli --help)
            display_result "Version"
            ;;
    esac
done

