## Привет 👋
В этой статье я бы хотел рассказать про установку быстрого и защищенного VPN: Wireguard. Сейчас в России блокируют популярные VPN-сервисы, и я научу вас, как создать собственный VPN за 5 минут

1. Для начала, нам потребуется VPS/VDS-сервер, купить его можно у [Aeza](https://aeza.net/?ref=349240), [FirstByte](https://firstbyte.ru), [SRV.Cheap](https://srv.cheap), [HostVDS](https://hostvds.com) и множества других провайдеров, которые принимают оплату по русским картам  
2. После того, как мы купили сервер, нужно зайти в SSH через [Putty](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) либо через [BitVise](https://bitvise.com)  
3. После того, как мы зашли в SSH, потребуется [перейти на сайт](https://github.com/dotmix/wireguard-ru) и скачать мой русский установщик WireGuard, либо прописать команду: `curl -O https://github.com/dotmix/wireguard-ru/releases/download/v1.0/wireguard-ru.sh`, затем `chmod +x wireguard-ru.sh`, и затем `./wireguard-ru.sh`  
![image](https://user-images.githubusercontent.com/102430482/172452974-88b3812d-9602-42fc-a2bd-5fbf2d65f128.png)
4. Далее, нажимаем Enter, когда предлагается ввести данные, поля будут заполнены автоматически (я замазал некоторые данные для безопасности)  
![image](https://user-images.githubusercontent.com/102430482/172453659-41eb57f7-4c45-4961-ac69-3df93f0d0705.png)
5. Далее нам предлагается ввести имя пользователя, вводим любое имя, которое Вам удобно (оно будет храниться в названии файла профиля подключения и в базе пользователей)  
![image](https://user-images.githubusercontent.com/102430482/172453969-a74cd92b-e7fb-44c5-9577-4fafdda14b83.png)
6. После заполнения всех полей, будет сообщение об успешной установке, и в консоль отправится QR-код, он нужен для подключения мобильных устройств  
![image](https://user-images.githubusercontent.com/102430482/172454295-305b2fcf-6c53-439c-a230-5277eb48765a.png)  
![image](https://user-images.githubusercontent.com/102430482/172454334-60d131e9-6c99-47f3-badc-faa820582c6b.png)  
7. Если Вы захотите добавить еще одного пользователя или удалить его, либо же удалить WireGuard с сервера, достаточно запустить скрипт еще раз, и нам будет предложено выбрать действие  
![image](https://user-images.githubusercontent.com/102430482/172454522-e9632b90-aa1a-4265-9084-119918e811e2.png)

#### Спасибо за прочтение статьи, вы научились устанавливать WireGuard всего за 5 минут!
