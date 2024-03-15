import os
import re

def process_md_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 使用正则表达式替换文件路径格式
    # pattern = r'\]\(/[^/]+/([^)]+\))'
    pattern = r'\]\((?:\./)?[^/)]+/([^/)]+\.(?:png|jpg|jpeg))\)'
    new_content = re.sub(pattern, r'](\1)', content)
    # 找出所有替换的内容
    # print(re.findall(pattern, content))
    # print(new_content.)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

def process_md_files_in_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.md'):
                file_path = os.path.join(root, file)
                process_md_file(file_path)
                print(f"Processed {file_path} done")

if __name__ == "__main__":
    directory = '.'  # 指定目录
    process_md_files_in_directory(directory)
    print("Done!")
