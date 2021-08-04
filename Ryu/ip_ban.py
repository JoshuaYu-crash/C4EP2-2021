from transinfo_server import ban


def add_danger_ip(saddr):
    ban(saddr, banned=True)


def add_doubt_ip(saddr):
    ban(saddr, banned=False)
