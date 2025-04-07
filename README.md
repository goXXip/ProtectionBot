# ProtectionBot
irc protection bot auto gline spam ip 

IRC botunuzu arka planda (daemon olarak) çalıştırmak için aşağıdaki yöntemlerden birini kullanabilirsiniz:
1. screen/tmux ile Çalıştırma (Basit Yöntem)
screen kullanarak:
bash
Copy

# screen kurulumu (yoksa)
sudo apt-get install screen

# Yeni bir screen oturumu oluştur
screen -S ircbot

# Botu çalıştır
node bot.js

# Screen'den çıkmak için Ctrl+A, ardından D tuşlarına bas
# (Detach işlemi, bot arka planda çalışmaya devam eder)

# Tekrar bağlanmak için:
screen -r ircbot

tmux kullanarak (daha modern alternatif):
bash
Copy

# tmux kurulumu
sudo apt-get install tmux

# Yeni oturum başlat
tmux new -s ircbot

# Botu çalıştır
node bot.js

# Oturumdan ayrılmak için Ctrl+B, ardından D
# Tekrar bağlanmak için:
tmux attach -t ircbot

2. systemd ile Servis Oluşturma (Profesyonel Yöntem)

    Servis dosyası oluşturun:

bash
Copy

sudo nano /etc/systemd/system/ircbot.service

    Aşağıdaki içeriği ekleyin (yolları kendi sisteminize göre düzenleyin):

ini
Copy

[Unit]
Description=IRC SpamGuard Bot
After=network.target

[Service]
Type=simple
User=nodeuser
WorkingDirectory=/path/to/your/bot
ExecStart=/usr/bin/node /path/to/your/bot/bot.js
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ircbot

[Install]
WantedBy=multi-user.target

    Servisi etkinleştirin ve başlatın:

bash
Copy

sudo systemctl daemon-reload
sudo systemctl enable ircbot
sudo systemctl start ircbot

    Durumunu kontrol edin:

bash
Copy

sudo systemctl status ircbot
# Logları görüntülemek için:
journalctl -u ircbot -f

3. PM2 ile Çalıştırma (Node.js için Özel)

    PM2'yi kurun:

bash
Copy

npm install -g pm2

    Botu PM2 ile başlatın:

bash
Copy

pm2 start bot.js --name "ircbot"

    PM2'yi startup script olarak ekleyin (sunucu restartta otomatik başlasın):

bash
Copy

pm2 startup
pm2 save

    Yönetim komutları:

bash
Copy

# Durumu görüntüle
pm2 status

# Logları izle
pm2 logs ircbot

# Botu durdur
pm2 stop ircbot

# Botu yeniden başlat
pm2 restart ircbot

4. nohup ile Çalıştırma (Hızlı Çözüm)
bash
Copy

nohup node bot.js > bot.log 2>&1 &

    Çıktılar bot.log dosyasına yazılır

    Süreci görmek için: ps aux | grep node

    Süreci sonlandırmak için: kill <PID>

Önemli Notlar:

    Log Yönetimi:

        systemd veya PM2 kullanıyorsanız otomatik log kaydı yapacaktır

        Manuel çalıştırıyorsanız logları dosyaya yönlendirin

    Botun Çökmesi Durumu:

        systemd ve PM2 otomatik restart özelliğine sahiptir

        Diğer yöntemlerde bot çökerse yeniden başlatmanız gerekir

    Güvenlik:

        Botu özel bir kullanıcı ile çalıştırın:
    bash
    Copy

    sudo adduser --disabled-password --gecos "" nodeuser
    sudo chown -R nodeuser:nodeuser /path/to/your/bot

Hangi yöntemi seçerseniz seçin, botunuz artık arka planda sorunsuz çalışacak ve sunucu restartlarında otomatik başlayacaktır.
