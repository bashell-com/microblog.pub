import emoji


def flexmoji(html):
    html = emoji.emojize(html, use_aliases=True)
    html = emoji.emojize(html, use_aliases=True, delimiters=(':blob_', ':'))
    html = emoji.emojize(html, use_aliases=True, delimiters=(':blob', ':'))
    return html
