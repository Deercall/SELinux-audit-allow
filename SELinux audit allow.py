import os
import re
import time


start_time = time.time()

def extract_field(error, keyword):
    match = re.search(f"{keyword}=([^\s]+)", error)
    if match:
        return match.group(1).replace('u:r:', '').replace('u:object_r:', '').replace(':s0', '')
    return None

script_dir = os.path.dirname(os.path.abspath(__file__))
sepolicy_rule = os.path.join(script_dir, 'sepolicy.rule')
sepolicy_cil = os.path.join(script_dir, 'sepolicy.cil')
rules = 0

print("- SELinux audit allow")
print("- 版本: 1.0.0")
print("原作者:酷安@Enmmmmmm")
print("修改者:酷安@猫羽今天吃什么")

file = ""
while not file:
    input_file = input("- 请输入目标日志文件\n- (点击屏幕输入): ")
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

rule_list = []
unique_rules = set()

for target in [sepolicy_rule, sepolicy_cil]:
    if os.path.isfile(target) and os.path.getsize(target) > 0:
        action = input(f"\n! 目标输出文件 {target} 已存在\n- 您希望继续写入此文件吗?\n- 输入 y 或 yes 将会继续写入此文件\n- 输入 n 或 no 将会清空此文件\n- 输入任意内容退出脚本: ")
        if action.lower() in ["y", "yes"]:
            print(f"- 继续写入 {target}")
            with open(target, 'r', encoding='utf-8') as f:
                for line in f:
                    line = re.sub(r"[{}()]", "", line.strip()).replace('allow ', '')
                    if line:
                        rule_list.append(line)
                        unique_rules.add(line)
        elif action.lower() in ["n", "no"]:
            print(f"- 清空 {target}")
            with open(target, 'w', encoding='utf-8') as f:
                f.write('')
        else:
            exit(1)
    else:
        with open(target, 'w', encoding='utf-8') as f:
            f.write('')

print("\n- 处理")
print("- 读取日志文件")
with open(file, 'r', encoding='utf-8') as f:
    log = [line for line in f.readlines() if "avc:  denied" in line and "untrusted_app" not in line]

if not log:
    print("! 读取日志文件失败")
    exit(1)

print("- 开始生成规则")

excluded_classes = ["flags_health_check"]
rule_entries = []

for error in log:
    scontext = extract_field(error, "scontext")
    tcontext = extract_field(error, "tcontext")
    tclass = extract_field(error, "tclass")
    perms = re.search(r"{([^}]+)}", error)
    perms = perms.group(1).strip() if perms else ""
    all_config = f"{scontext} {tcontext} {tclass}"

    if tclass in excluded_classes:
        continue

    if not scontext or not tcontext or not tclass or not perms:
        continue

    rule = f"{all_config} {perms}"

    if rule in unique_rules:
        continue

    existing_entry = next((entry for entry in rule_entries if entry[0] == all_config), None)
    if existing_entry:
        existing_entry[1].extend(perms.split())
        rule_entries.remove(existing_entry)
    else:
        rule_entries.append([all_config, perms.split()])

    unique_rules.add(rule)
    rules += 1

    print(f"\n- 第 {rules} 条规则")
    print(f"- 信息: scontext={scontext}, tcontext={tcontext}, tclass={tclass}, perms={perms}")

print("- 写入规则到文件")

with open(sepolicy_rule, 'a', encoding='utf-8') as rule_file, open(sepolicy_cil, 'a', encoding='utf-8') as cil_file:
    for all_config, perms in rule_entries:
        perm_str = ' '.join(perms)
        rule_file.write(f"allow {all_config} {{ {perm_str} }}\n")
        cil_file.write(f"(allow {all_config.split()[0]} {all_config.split()[1]} ({all_config.split()[2]} (({perm_str}))))\n")

print("\n- 规则生成完成\n")

end_time = time.time()
total_time = end_time - start_time
print(f"\n- 完成，总耗时: {total_time:.2f} 秒")
exit(0)
