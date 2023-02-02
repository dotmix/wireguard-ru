## Привет 👋
В этой статье я бы хотел рассказать про установку быстрого и защищенного VPN: Wireguard. Сейчас в России блокируют популярные VPN-сервисы, и я научу вас, как создать собственный VPN за 5 минут

1. Для начала, нам потребуется VPS/VDS-сервер, купить его можно у [Aeza](https://aeza.net/?ref=349240), [FirstByte](https://firstbyte.ru), [DeltonCloud](https://delton.cloud), [HostVDS](https://hostvds.com) и множества других провайдеров, которые принимают оплату по русским картам  
2. После того, как мы купили сервер, нужно зайти в SSH через [Putty](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) либо через [BitVise](https://bitvise.com)  
3. После того, как мы зашли в SSH, потребуется [перейти на сайт](https://github.com/dotmix/wireguard-ru) и скачать мой русский установщик WireGuard, либо прописать команды (поочередно):  
```
sudo apt update && sudo apt install -y curl && curl -O https://raw.githubusercontent.com/dotmix/wireguard-ru/main/wireguard-ru.sh
sudo chmod +x wireguard-ru.sh
./wireguard-ru.sh
```  
![image](https://user-images.githubusercontent.com/102430482/216429733-5419613e-d186-427f-b252-60387a3786c8.png)  
4. Далее, нажимаем Enter, когда предлагается ввести данные, поля будут заполнены автоматически  
![image](https://user-images.githubusercontent.com/102430482/216428935-262dbff8-5502-4876-85ca-93c9afbd7d1d.png)
5. Далее нам предлагается ввести имя пользователя, вводим любое имя, которое Вам удобно (оно будет храниться в названии файла профиля подключения и в базе пользователей)  
![image](https://user-images.githubusercontent.com/102430482/216429133-247564c0-e214-487b-ba22-5ea5a6a755c4.png)  
6. После заполнения всех полей, будет сообщение об успешной установке, и в консоль отправится QR-код, он нужен для подключения мобильных устройств  
![image](https://user-images.githubusercontent.com/102430482/216430093-ce21998f-81b2-4f74-84a3-409b37c5a87e.png)  
![image](https://user-images.githubusercontent.com/102430482/216429441-c2a7dd6b-2a67-4c22-87a0-199b30134d23.png)  
7. Если Вы захотите добавить еще одного пользователя или удалить его, либо же удалить WireGuard с сервера, достаточно запустить скрипт еще раз, и нам будет предложено выбрать действие  
![image](https://user-images.githubusercontent.com/102430482/216429546-3ac275fb-c54c-4ba8-9156-25cfbf3c8761.png)  

#### Спасибо за прочтение статьи, вы научились устанавливать WireGuard всего за 5 минут!
