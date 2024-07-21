import os
import re
import time

def extract_field(error, keyword):
    match = re.search(f"{keyword}=([^\s]+)", error)
    if match:
        return match.group(1).replace('u:r:', '').replace('u:object_r:', '').replace(':s0', '')
    return None

def remove_empty_lines(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [line for line in f.readlines() if line.strip()]
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("".join(lines))

def merge_permissions(existing_perms, new_perms):
    existing_perm_set = set(existing_perms.split())
    new_perm_set = set(new_perms.split())
    return ' '.join(sorted(existing_perm_set.union(new_perm_set)))

script_dir = os.path.dirname(os.path.abspath(__file__))
sepolicy_rule = os.path.join(script_dir, 'sepolicy.rule')
sepolicy_cil = os.path.join(script_dir, 'sepolicy.cil')
rules = 0

print("========SELinux audit allow========")

file = ""
while not file:
    input_file = input("- 请输入目标日志文件: ")
    if input_file == "exit":
        exit()

    if os.path.isfile(os.path.join(script_dir, input_file)):
        file = os.path.join(script_dir, input_file)
    elif os.path.isfile(input_file):
        file = input_file
    else:
        print(f"! 未找到日志文件: {input_file}\n")

print(f"\n- 目标日志文件: {file}")
print(f"- 目标输出文件: {sepolicy_rule}, {sepolicy_cil}")

def handle_target_file(target):
    if os.path.isfile(target) and os.path.getsize(target) > 0:
        action = input(f"\n! 目标输出文件 {target} 已存在\n- 您希望继续写入此文件吗?\n- 输入 y 或 yes 将会继续写入此文件\n- 输入 n 或 no 将会清空此文件: ")
        if action.lower() in ["y", "yes"]:
            print(f"- 继续写入 {target}")
            with open(target, 'r', encoding='utf-8') as f:
                return re.sub(r"[{}()]", "", f.read()).replace('allow ', '')
        elif action.lower() in ["n", "no"]:
            print(f"- 清空 {target}")
            open(target, 'w').close()
            return ""
    else:
        open(target, 'w').close()
        return ""

rule_list = ""
for target in [sepolicy_rule, sepolicy_cil]:
    rule_list += handle_target_file(target)

start_time = time.time()

with open(file, 'r', encoding='utf-8') as f:
    log = [line for line in f if "avc:  denied" in line and "untrusted_app" not in line]

if not log:
    print("! 读取日志文件失败")
    exit(1)

rules_text_rule = ""
rules_text_cil = ""

rules_dict = {}

for error in log:
    scontext = extract_field(error, "scontext")
    tcontext = extract_field(error, "tcontext")
    tclass = extract_field(error, "tclass")
    perms_match = re.search(r"{([^}]+)}", error)
    perms = perms_match.group(1).strip() if perms_match else ""
    all_config = f"{scontext} {tcontext} {tclass}"

    if not scontext or not tcontext or not tclass or not perms:
        continue

    if all_config in rules_dict:
        existing_perms = rules_dict[all_config]
        merged_perms = merge_permissions(existing_perms, perms)
        rules_dict[all_config] = merged_perms
    else:
        rules_dict[all_config] = perms

for all_config, perms in rules_dict.items():
    scontext, tcontext, tclass = all_config.split(' ', 2)
    rules_text_rule += f"allow {scontext} {tcontext} {tclass} {{ {perms} }}\n"
    rules_text_cil += f"(allow {scontext} {tcontext} ({tclass} ({perms})))\n"
    rules += 1

with open(sepolicy_rule, 'a', encoding='utf-8') as f:
    f.write(rules_text_rule)

with open(sepolicy_cil, 'a', encoding='utf-8') as f:
    f.write(rules_text_cil)

remove_empty_lines(sepolicy_rule)
remove_empty_lines(sepolicy_cil)

end_time = time.time()
elapsed_time = end_time - start_time

print(f"- 规则生成完成，共生成 {rules} 条规则，耗时 {elapsed_time:.2f} 秒")
exit(0)
