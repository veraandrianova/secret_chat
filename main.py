import asyncio

from pywebio import start_server
from pywebio.input import *
from pywebio.output import *
from pywebio.session import defer_call, info as session_info, run_async, run_js
from config import get_keys, check_signature, get_public_key, create_signature

chat_msgs = []
owner = {}
friend = []
MAX_MESSAGES_COUNT = 100


async def main():
    global chat_msgs
    global friend
    global owner
    put_markdown("## 🧊 Добро пожаловать в онлайн чат!\nИсходный код данного чата укладывается в 100 строк кода!")

    msg_box = output()
    put_scrollable(msg_box, height=300, keep_bottom=True)

    nickname = await input("Войти в чат", required=True, placeholder="Ваше имя",
                           validate=lambda n: "Такой ник уже используется!" if n in owner or n == '📢' else None)
    if len(owner) == 0:
        pubkey = get_keys(nickname)
        put_file(f"{nickname}_public.pem", pubkey)
        owner['nick'] = nickname
        data_user = await input_group("Добавить пользователя", [
            input(placeholder="Добавить пользователя", name="add"),
            actions(name="cmd", buttons=["Добавить", {'label': "Выйти из чата", 'type': 'cancel'}])
        ])
        friend.append(data_user.get('add'))
    else:
        if nickname in friend:
            pubkey = get_keys(nickname)
            put_file(f"{nickname}_public.pem", pubkey)
            chat_msgs.append(('📢', f'`{nickname}` присоединился к чату!'))
            msg_box.append(put_markdown(f'📢 `{nickname}` присоединился к чату'))
        else:
            chat_msgs.append(('📢', f'`{nickname}` пытается присоединиться к чату!'))
    refresh_task = run_async(refresh_msg(nickname, msg_box))

    while True:
        data = await input_group("💭 Новое сообщение", [
            input(placeholder="Текст сообщения ...", name="msg"),
            file_upload(placeholder="Публичный ключ ...", name="public_key"),
            checkbox(options=['Подписать'], name="signature"),
            actions(name="cmd", buttons=["Отправить сообщение", {'label': "Выйти из чата", 'type': 'cancel'}])
        ], validate=lambda m: ('msg', "Введите текст сообщения!") if m["cmd"] == "Отправить" and not m['msg'] else None)
        if data is None:
            break
        current_signature = data.get('signature')
        if len(current_signature) > 0 and data.get('public_key') is not None:
            signature = create_signature(nickname, data.get('msg'))
            public_key = data.get('public_key')['content'].decode("utf-8")
            if check_signature(public_key, signature, data.get('msg')):
                msg_box.append(put_markdown(f"`{nickname}`: {data['msg']}"))
                chat_msgs.append((nickname, data['msg']))
            else:
                msg_box.append(put_markdown(f"Ошибка шифрования"))
                chat_msgs.append((nickname, f"Ошибка шифрования"))
        else:
            msg_box.append(put_markdown(f"Отправить можно только подписанные данные и с публичным ключем"))
            chat_msgs.append((nickname, f"Отправить можно только подписанные данные и с публичным ключем"))

    refresh_task.close()
    owner.clear()
    toast("Вы вышли из чата!")
    msg_box.append(put_markdown(f'📢 Пользователь `{nickname}` покинул чат!'))
    chat_msgs.append(('📢', f'Пользователь `{nickname}` покинул чат!'))

    put_buttons(['Перезайти'], onclick=lambda btn: run_js('window.location.reload()'))


async def refresh_msg(nickname, msg_box):
    global chat_msgs
    last_idx = len(chat_msgs)

    while True:
        await asyncio.sleep(1)

        for m in chat_msgs[last_idx:]:
            if m[0] != nickname:  # if not a message from current user
                msg_box.append(put_markdown(f"`{m[0]}`: {m[1]}"))

        if len(chat_msgs) > MAX_MESSAGES_COUNT:
            chat_msgs = chat_msgs[len(chat_msgs) // 2:]

        last_idx = len(chat_msgs)


if __name__ == "__main__":
    start_server(main, debug=True, port=8080, cdn=False)