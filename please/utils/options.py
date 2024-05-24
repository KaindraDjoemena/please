def format_options(options, cur_loc) -> str:
    updated = []

    for i in range(len(options)):
        if i == cur_loc:
            updated.append(f"[reverse][{i+1}] {options[i][0]}[/reverse]")
        else:
            updated.append(f"[{i+1}] {options[i][0]}")

    return "\n".join(updated)