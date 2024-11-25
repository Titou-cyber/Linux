## TP Avancé : "Mission Ultime : Sauvegarde et Sécurisation"

* Étape 1 : Analyse et nettoyage du 

Lister les tâches cron pour détecter des backdoors :

````
 crontab -u $user -l
*/10 * * * * /tmp/.hidden_script
````

Identifier et supprimer les fichiers cachés :

````
[root@localhost ~]# sudo find /tmp -type f -name ".*" -print
/tmp/.hidden_script
/tmp/.hidden_file
````
````
[root@localhost ~]# sudo head -n 20 /tmp/.hidden_script
malicious script
````
````
[root@localhost ~]# sudo rm /tmp/.hidden_script
````
````
[root@localhost ~]# sudo find /var/tmp -type f -name ".*" -print
/var/tmp/.nop
....
````

Analyser les connexions réseau actives :

````
ss -a
````
* Étape 2 : Configuration avancée de LVM

Créer un snapshot de sécurité pour /mnt/secure_data :

````
[root@localhost ~]# vgs
  VG        #PV #LV #SN Attr   VSize    VFree
  rl_vbox     1   2   0 wz--n-   <4.00g      0
  vg_secure   1   1   0 wz--n- 1020.00m 520.00m
````
````
[root@localhost ~]# lvcreate --size 1G --snapshot --name secure_data_snap /dev/vg_secure/secure_data
  Reducing COW size 1.00 GiB down to maximum usable size 504.00 MiB.
  Logical volume "secure_data_snap" created.
````
````
[root@localhost ~]# ls /mnt/secure_data_snap
lost+found  sensitive1.txt  sensitive2.txt
````
````
[root@localhost ~]# rm /mnt/secure_data/sensitive1.txt
rm: remove regular file '/mnt/secure_data/sensitive1.txt'? y
````
````
[root@localhost ~]# ls /mnt/secure_data
lost+found  sensitive2.txt
````
````
[root@localhost ~]# lvconvert --merge /dev/vg_secure/secure_data_snap
  Delaying merge since origin is open.
  Merging of snapshot vg_secure/secure_data_snap will occur on next activation of vg_secure/secure_data.
````
````
[root@localhost ~]# reboot
````
````
[root@localhost ~]# ls /mnt/secure_data
lost+found  sensitive1.txt  sensitive2.txt
````
Optimiser l’espace disque :

````
[root@localhost ~]# df -h /mnt/secure_data
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/vg_secure-secure_data  459M   16K  430M   1% /mnt/secure_data
````
````
[root@localhost ~]# lvextend -L+0.4G /dev/vg_secure/secure_data
  Rounding size to boundary between physical extents: 412.00 MiB.
  Size of logical volume vg_secure/secure_data changed from 500.00 MiB (125 extents) to 912.00 MiB (228 extents).
  Logical volume vg_secure/secure_data successfully resized.
````

* Étape 3 : Automatisation avec un script de sauvegarde

Créer un script secure_backup.sh :

````
#!/bin/bash

# Variables
SOURCE_DIR="/mnt/secure_data"
BACKUP_DIR="/backup"
DATE=$(date +%Y%m%d)
BACKUP_FILE="$BACKUP_DIR/secure_data_$DATE.tar.gz"

tar --exclude='*.tmp' --exclude='*.log' --exclude='.*' -czf $BACKUP_FILE $SOURCE_DIR

find $BACKUP_DIR -name "secure_data_*.tar.gz" -mtime +7 -exec rm {} \;

if [ -f $BACKUP_FILE ]; then
    echo "Sauvegarde créée avec succès : $BACKUP_FILE"
else
    echo "Erreur lors de la création de la sauvegarde"
fi
````

Testez le script :

````
[root@localhost ~]# /root/secure_backup.sh
tar: Removing leading `/' from member names
Sauvegarde créée avec succès : /backup/secure_data_20241125.tar.gz
````

Automatisez avec une tâche cron :

````
[root@localhost ~]# crontab -e
````
````
0 3 * * * /root/secure_backup.sh
````

* Étape 4 : Surveillance avancée avec auditd

Configurer auditd pour surveiller /etc :

````
[root@localhost ~]# sudo systemctl start auditd
````
````
[root@localhost ~]# sudo systemctl enable auditd
````
````
[root@localhost ~]# sudo auditctl -w /etc -p wa -k etc_watch
````

Tester la surveillance :

````
[root@localhost ~]# sudo touch /etc/test_audit
sudo echo "test" > /etc/test_audit
````

Analyser les événements :

````
[root@localhost ~]# sudo ausearch -k etc_watch
````
````
time->Mon Nov 25 12:34:19 2024
type=PROCTITLE msg=audit(1732534459.021:387): proctitle="-bash"
type=PATH msg=audit(1732534459.021:387): item=1 name="/etc/test_audit" inode=33378 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1732534459.021:387): item=0 name="/etc/" inode=18 dev=fd:00 mode=040755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1732534459.021:387): cwd="/root"
type=SYSCALL msg=audit(1732534459.021:387): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=5639dfbae2f0 a2=241 a3=1b6 items=2 ppid=1392 pid=2051 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="etc_watch"
````
````
[root@localhost ~]# sudo ausearch -k etc_watch > /var/log/audit_etc.log
````

* Étape 5 : Sécurisation avec Firewalld

````

Configurer un pare-feu pour SSH et HTTP/HTTPS uniquement :

````
[root@localhost ~]# 
sudo systemctl start firewalld
sudo systemctl enable firewalld
````
````
[root@localhost ~]# sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
````
````
[root@localhost ~]# sudo firewall-cmd --permanent --set-default-zone=drop
sudo firewall-cmd --reload
````

Bloquer des IP suspectes :

````
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.56.1" reject'
sudo firewall-cmd --reload
````

Restreindre SSH à un sous-réseau spécifique :

````
[root@localhost ~]# sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" service name="ssh" reject'
sudo firewall-cmd --reload
````