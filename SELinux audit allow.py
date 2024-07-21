import os
import re
import time


start_time = time.time()

def extract_field(error, keyword):
    match = re.search(f"{keyword}=([^\s]+)", error)
    if match:
        return match.group(1).replace('u:r:', '').replace('u:object_r:', '').replace(':s0', '')
    return None

def find_permissions(rule_list, all_config):
    perms = re.search(f"{re.escape(all_config)} (.+)", rule_list)
    if perms:
        return perms.group(1)
    return ""

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
    input_file = input("- 请输入目标日志文件\n- (文件名+格式): ")
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

for target in [sepolicy_rule, sepolicy_cil]:
    if os.path.isfile(target) and os.path.getsize(target) > 0:
        action = input(f"\n! 目标输出文件 {target} 已存在\n- 您希望继续写入此文件吗?\n- 输入 y 或 yes 将会继续写入此文件\n- 输入 n 或 no 将会清空此文件\n- 输入任意内容退出脚本: ")
        if action.lower() in ["y", "yes"]:
            print(f"- 继续写入 {target}")
            with open(target, 'r', encoding='utf-8') as f:
                rule_list = re.sub(r"[{}()]", "", f.read()).replace('allow ', '')
        elif action.lower() in ["n", "no"]:
            print(f"- 清空 {target}")
            open(target, 'w').close()
        else:
            exit(1)
    else:
        open(target, 'w').close()

print("\n- 处理")
print("- 读取日志文件")
with open(file, 'r', encoding='utf-8') as f:
    log = [line for line in f.readlines() if "avc:  denied" in line and "untrusted_app" not in line]

if not log:
    print("! 读取日志文件失败")
    exit(1)

print("- 开始生成规则")
rule_list = ""

for error in log:
    scontext = extract_field(error, "scontext")
    tcontext = extract_field(error, "tcontext")
    tclass = extract_field(error, "tclass")
    perms = re.search(r"{([^}]+)}", error)
    perms = perms.group(1).strip() if perms else ""
    all_config = f"{scontext} {tcontext} {tclass}"

    rules += 1
    print(f"\n- 此为第 {rules} 条规则")

    if not scontext or not tcontext or not tclass or not perms:
        print("! 信息获取失败")
        continue

    print(f"- 信息: scontext={scontext}, tcontext={tcontext}, tclass={tclass}, perms={perms}")

    if perms in find_permissions(rule_list, all_config):
        print("! 检测到重复规则, 跳过")
        continue

    if all_config in rule_list:
        existing_perms = find_permissions(rule_list, all_config)
        perms = f"{existing_perms} {perms}"
        rule_list = rule_list.replace(f"{all_config} {existing_perms}", "")

        with open(sepolicy_rule, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace(f"allow {all_config} {existing_perms}", "")
        with open(sepolicy_rule, 'w', encoding='utf-8') as f:
            f.write(content)

        with open(sepolicy_cil, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace(f"(allow {scontext} {tcontext} ({tclass} ({existing_perms})))", "")
        with open(sepolicy_cil, 'w', encoding='utf-8') as f:
            f.write(content)

    print(f"- MagiskPolicy 规则: allow {scontext} {tcontext} {tclass} {{ {perms} }}")
    print(f"- SEPolicy Cil 规则: (allow {scontext} {tcontext} ({tclass} (({perms}))))")

    with open(sepolicy_rule, 'a', encoding='utf-8') as f:
        f.write(f"allow {scontext} {tcontext} {tclass} {{ {perms} }}\n")

    with open(sepolicy_cil, 'a', encoding='utf-8') as f:
        f.write(f"(allow {scontext} {tcontext} ({tclass} (({perms}))))\n")

    rule_list += f"{all_config} {perms}\n"

def remove_empty_lines(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [line for line in f.readlines() if line.strip()]
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("".join(lines))

remove_empty_lines(sepolicy_rule)
remove_empty_lines(sepolicy_cil)

print("\n- 规则生成完成\n")

end_time = time.time()
total_time = end_time - start_time
print(f"\n- 完成，总耗时: {total_time:.2f} 秒")
exit(0)
