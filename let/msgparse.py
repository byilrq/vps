
def thread_message(thread, ai_description):
    msg = (
        f"{thread['domain'].upper()} 新促销\n"
        f"{thread['title']}\n"
        f"[{thread['creator']}] {thread['pub_date'].strftime('%Y/%m/%d %H:%M')}\n\n"
        + (
            f"{ai_description.strip()}"
            + ("..." if len(ai_description) > 200 else "")
            + "\n\n"
            if ai_description else ""
        )
        + f"原文链接: {thread['link']}"
    )
    return msg

def comment_message(thread, comment, ai_description):
    msg = (
        f"{thread['domain'].upper()} 新评论\n"
        f"[{comment['author']}] {comment['created_at'].strftime('%Y/%m/%d %H:%M')}\n\n"
        + (
            f"{ai_description.strip()}"
            + ("..." if len(ai_description) > 200 else "")
            + "\n"
            if ai_description else ""
        )
        + f"\n原文链接: {comment['url']}"
    )
    return msg


def watched_comment_message(thread, comment, translated_text):
    """手动爬楼中的指定用户评论，完整展示汉化内容及原文地址。"""
    return (
        f"{thread['domain'].upper()} 关注用户新评论\n"
        f"用户：{comment['author']}\n"
        f"主题：{thread.get('title', '')}\n"
        f"时间：{comment['created_at'].strftime('%Y/%m/%d %H:%M')}\n\n"
        f"{str(translated_text).strip()}\n\n"
        f"原文链接：{comment['url']}"
    )

