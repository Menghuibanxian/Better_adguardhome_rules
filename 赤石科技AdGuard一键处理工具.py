import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
import os
from collections import Counter
import requests
import re
from datetime import datetime
import threading

class OneClickProcessor:
    def __init__(self, root):
        self.root = root
        self.root.title("AdGuard 规则一键处理工具")
        self.root.geometry("800x600")
        self.config_file = "user_rules_config.json"  # 用户配置文件
        
        # 创建主框架
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(main_frame, text="AdGuard 规则一键处理工具", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # 创建标签页
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 一键处理标签页
        self.create_auto_process_tab(notebook)
        
        # 域名规则管理标签页
        self.create_domain_rule_tab(notebook)
        print("OneClickProcessor 初始化完成")
        
    def create_auto_process_tab(self, notebook):
        """创建一键处理标签页"""
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="一键处理")
        
        # 说明文本
        info_text = """
一键处理流程：
1. 域名统计：分析日志文件，生成域名访问统计 (1.txt)
2. 规则合并：下载并合并多个规则源 (2.txt)
3. 规则精简：根据统计结果精简规则 (optimized_rules.txt)

使用说明：
1. 点击"选择日志文件"按钮选择.json、.json.1或.1后缀的文件（可多选）
2. 在域名规则管理标签页中添加规则源URL
3. 点击下方"开始一键处理"按钮
        """
        info_label = ttk.Label(tab, text=info_text.strip(), justify=tk.LEFT)
        info_label.pack(pady=(0, 10))
        
        # 日志文件选择区域
        log_frame = ttk.LabelFrame(tab, text="日志文件选择")
        log_frame.pack(fill=tk.X, pady=(0, 10))
        
        button_frame = ttk.Frame(log_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="选择日志文件", command=self.select_log_files).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="清空文件列表", command=self.clear_log_files).pack(side=tk.LEFT, padx=(5, 0))
        
        # 日志文件列表
        self.log_files_listbox = tk.Listbox(log_frame, height=6)
        self.log_files_listbox.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        # 控制按钮
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.process_button = ttk.Button(control_frame, text="开始一键处理", command=self.start_processing)
        self.process_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 日志显示区域
        log_display_frame = ttk.LabelFrame(tab, text="处理日志")
        log_display_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_display_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 文件列表
        self.log_files = []
        
    def create_domain_rule_tab(self, notebook):
        """创建域名规则管理标签页"""
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="域名规则管理")
        
        # 说明文本
        info_text = """
在此添加或删除规则源URL：
- 点击"添加URL"按钮添加新的规则源
- 选中列表中的URL后点击"删除选中"按钮删除
- 点击"保存规则列表"按钮保存到rules.txt文件
        """
        info_label = ttk.Label(tab, text=info_text.strip(), justify=tk.LEFT)
        info_label.pack(pady=(0, 10))
        
        # URL输入区域
        url_input_frame = ttk.Frame(tab)
        url_input_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(url_input_frame, text="规则源URL:").pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(url_input_frame)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(url_input_frame, text="添加URL", command=self.add_url).pack(side=tk.RIGHT)
        
        # URL列表区域
        url_list_frame = ttk.LabelFrame(tab, text="规则源列表")
        url_list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # URL列表
        self.url_listbox = tk.Listbox(url_list_frame)
        self.url_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # URL操作按钮
        url_button_frame = ttk.Frame(url_list_frame)
        url_button_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(url_button_frame, text="删除选中", command=self.remove_selected_url).pack(side=tk.LEFT)
        ttk.Button(url_button_frame, text="清空列表", command=self.clear_urls).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Button(url_button_frame, text="从文件加载", command=self.load_urls_from_file).pack(side=tk.RIGHT)
        ttk.Button(url_button_frame, text="保存规则列表", command=self.save_urls_to_file).pack(side=tk.RIGHT, padx=(0, 5))
        
        # 加载默认规则源
        self.load_default_urls()
        
    def load_default_urls(self):
        """加载默认规则源"""
        # 先尝试加载用户保存的规则源
        if self.load_user_urls():
            return  # 如果成功加载了用户规则，则不加载默认规则
            
        # 如果没有用户规则，则加载默认规则
        default_urls = [
            "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
            "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
            "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Master/OtherRules/CoolapkRules.txt"
        ]
        
        for url in default_urls:
            self.url_listbox.insert(tk.END, url)
            
    def load_user_urls(self):
        """从配置文件加载用户自定义规则源"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    urls = config.get('user_urls', [])
                    for url in urls:
                        self.url_listbox.insert(tk.END, url)
                    return True
        except Exception as e:
            print(f"加载用户配置时出错: {e}")
        return False
        
    def save_user_urls(self):
        """保存用户自定义规则源到配置文件"""
        try:
            urls = list(self.url_listbox.get(0, tk.END))
            config = {'user_urls': urls}
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存用户配置时出错: {e}")
            
    def select_log_files(self):
        """选择日志文件"""
        files = filedialog.askopenfilenames(
            title="选择AdGuard日志文件",
            filetypes=[("JSON files", "*.json *.json.1 *.1"), ("All files", "*.*")]
        )
        for file in files:
            if file not in self.log_files:
                self.log_files.append(file)
                self.log_files_listbox.insert(tk.END, os.path.basename(file))
                
    def clear_log_files(self):
        """清空日志文件列表"""
        self.log_files.clear()
        self.log_files_listbox.delete(0, tk.END)
        
    def add_url(self):
        """添加URL到列表"""
        url = self.url_entry.get().strip()
        if url and url.startswith(('http://', 'https://')):
            self.url_listbox.insert(tk.END, url)
            self.url_entry.delete(0, tk.END)
            self.save_user_urls()  # 保存用户配置
        else:
            messagebox.showwarning("警告", "请输入有效的URL（以http://或https://开头）")
            
    def remove_selected_url(self):
        """删除选中的URL"""
        selection = self.url_listbox.curselection()
        if selection:
            self.url_listbox.delete(selection[0])
            self.save_user_urls()  # 保存用户配置
        else:
            messagebox.showwarning("警告", "请先选择要删除的URL")
            
    def clear_urls(self):
        """清空URL列表"""
        self.url_listbox.delete(0, tk.END)
        self.save_user_urls()  # 保存用户配置
        
    def load_urls_from_file(self):
        """从文件加载URL列表"""
        file_path = filedialog.askopenfilename(
            title="选择规则URL文件",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip() and not line.startswith('#') and line.startswith('http')]
                    self.url_listbox.delete(0, tk.END)
                    for url in urls:
                        self.url_listbox.insert(tk.END, url)
                self.save_user_urls()  # 保存用户配置
            except Exception as e:
                messagebox.showerror("错误", f"加载文件时出错:\n{str(e)}")
                
    def save_urls_to_file(self):
        """保存URL列表到文件"""
        file_path = filedialog.asksaveasfilename(
            title="保存规则URL列表",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                urls = list(self.url_listbox.get(0, tk.END))
                with open(file_path, 'w', encoding='utf-8') as f:
                    for url in urls:
                        f.write(url + '\n')
                messagebox.showinfo("完成", f"URL列表已保存到 {file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"保存文件时出错:\n{str(e)}")
        
    def log_message(self, message):
        """在日志区域显示消息"""
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.update()
        
    def count_domains_in_file(self, file_path):
        """统计单个文件中的域名出现次数"""
        domain_count = Counter()
        line_count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                while True:
                    line = f.readline()
                    if not line:  # 文件结束
                        break
                        
                    line_count += 1
                    
                    if line.strip():  # 忽略空行
                        try:
                            record = json.loads(line)
                            # 从QH字段获取域名
                            domain = record.get('QH', '')
                            if domain:
                                domain_count[domain] += 1
                        except json.JSONDecodeError:
                            # 忽略无法解析的行
                            continue
        except Exception as e:
            raise Exception(f"处理文件 {file_path} 时出错: {e}")
        
        return domain_count, line_count
        
    def download_rules(self, urls):
        """下载规则内容"""
        all_rules = []
        for i, url in enumerate(urls):
            self.log_message(f"正在下载 ({i+1}/{len(urls)}): {url}")
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    rules = response.text.split('\n')
                    all_rules.extend(rules)
                    self.log_message(f"成功下载 {len(rules)} 条规则")
                else:
                    self.log_message(f"下载失败: {url} (状态码: {response.status_code})")
            except Exception as e:
                self.log_message(f"下载出错 {url}: {str(e)}")
        return all_rules
        
    def clean_and_deduplicate(self, rules):
        """清理和去重规则"""
        # 使用有序字典保持顺序并去重
        unique_rules = dict()
        
        for rule in rules:
            rule = rule.strip()
            
            # 跳过空行和注释行
            if not rule or rule.startswith('!') or rule.startswith('#') or rule.startswith('[') or rule.startswith('//'):
                continue
                
            # 标准化规则（移除多余的空格）
            rule = re.sub(r'\s+', ' ', rule)
            
            # 以规则内容为键，避免重复
            unique_rules[rule] = True
            
        return list(unique_rules.keys())
        
    def save_rules(self, rules, output_file):
        """保存合并后的规则"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("! 合并后的AdGuard规则\n")
            f.write("! 规则数量: {}\n".format(len(rules)))
            f.write("! 最后更新: {}\n".format(datetime.now().strftime("%Y-%m-%d")))
            f.write("\n")
            for rule in rules:
                f.write(rule + '\n')
                
    def extract_domain_from_log_line(self, line):
        """从日志行中提取域名"""
        # 日志格式: domain.com 123
        parts = line.strip().split()
        if len(parts) >= 1:
            return parts[0]
        return None
        
    def extract_domain_from_rule(self, rule):
        """从AdGuard规则中提取域名"""
        # 移除行首的@@符号（例外规则）
        rule = rule.strip()
        if rule.startswith('@@'):
            rule = rule[2:]
        
        # 处理 ||domain.com^ 格式
        match = re.match(r'\|\|([^\^/]+)', rule)
        if match:
            return match.group(1)
        
        # 处理 domain.com^ 格式
        match = re.match(r'([^\^/]+)\^', rule)
        if match:
            return match.group(1)
        
        # 处理 0.0.0.0 domain.com 格式
        match = re.match(r'0\.0\.0\.0\s+([^\s]+)', rule)
        if match:
            return match.group(1)
        
        # 处理 IP 地址格式
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', rule)
        if match:
            return match.group(1)
        
        # 处理其他可能的域名格式
        match = re.match(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', rule)
        if match:
            return match.group(1)
        
        return None
        
    def process_thread(self):
        """处理线程"""
        try:
            self.root.after(0, lambda: self.process_button.config(state='disabled'))
            self.root.after(0, lambda: self.progress.start())
            
            self.log_message("开始一键处理流程...")
            
            # 步骤1：域名统计
            self.log_message("\n步骤1：执行域名统计...")
            
            if not self.log_files:
                raise Exception("未选择任何日志文件")
                
            self.log_message(f"找到 {len(self.log_files)} 个日志文件")
            
            # 统计域名
            total_count = Counter()
            for file_path in self.log_files:
                self.log_message(f"正在处理: {os.path.basename(file_path)}")
                file_count, line_count = self.count_domains_in_file(file_path)
                total_count.update(file_count)
                self.log_message(f"  处理完成，共处理 {line_count} 行")
                
            # 保存域名统计结果
            domain_count_file = "1.txt"
            with open(domain_count_file, 'w', encoding='utf-8') as f:
                for domain, count in sorted(total_count.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"{domain} {count}\n")
            self.log_message(f"域名统计完成，结果已保存到 {domain_count_file}")
            
            # 步骤2：规则合并
            self.log_message("\n步骤2：执行规则合并...")
            
            # 获取规则源URL
            urls = list(self.url_listbox.get(0, tk.END))
            
            if not urls:
                raise Exception("未找到有效的规则源URL")
                
            self.log_message(f"找到 {len(urls)} 个规则源")
            
            # 下载规则
            all_rules = self.download_rules(urls)
            self.log_message(f"总共下载了 {len(all_rules)} 条规则")
            
            # 去重和清理
            unique_rules = self.clean_and_deduplicate(all_rules)
            self.log_message(f"去重后剩余 {len(unique_rules)} 条有效规则")
            
            # 保存合并结果
            merged_rules_file = "2.txt"
            self.save_rules(unique_rules, merged_rules_file)
            self.log_message(f"规则合并完成，结果已保存到 {merged_rules_file}")
            
            # 步骤3：规则精简
            self.log_message("\n步骤3：执行规则精简...")
            
            # 读取日志文件中的域名
            log_domains = set()
            with open(domain_count_file, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = self.extract_domain_from_log_line(line)
                    if domain:
                        log_domains.add(domain)
            self.log_message(f"日志中找到 {len(log_domains)} 个唯一域名")
            
            # 读取规则文件并过滤
            filtered_rules = []
            total_rules = 0
            kept_rules = 0
            
            with open(merged_rules_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # 保留空行和注释行
                    if not line or line.startswith('!'):
                        filtered_rules.append(line)
                        continue
                    
                    total_rules += 1
                    domain = self.extract_domain_from_rule(line)
                    
                    # 如果能提取到域名且域名在日志中出现过，则保留规则
                    if domain and domain in log_domains:
                        filtered_rules.append(line)
                        kept_rules += 1
            
            # 写入精简后的规则文件
            optimized_rules_file = "optimized_rules.txt"
            with open(optimized_rules_file, 'w', encoding='utf-8') as f:
                for rule in filtered_rules:
                    f.write(rule + '\n')
            
            # 计算统计信息
            deleted_rules = total_rules - kept_rules
            reduction_percentage = (deleted_rules / total_rules * 100) if total_rules > 0 else 0
            
            self.log_message(f"原始规则总数: {total_rules}")
            self.log_message(f"保留规则数: {kept_rules}")
            self.log_message(f"删除规则数: {deleted_rules}")
            self.log_message(f"精简比例: {reduction_percentage:.2f}%")
            self.log_message(f"规则精简完成，结果已保存到 {optimized_rules_file}")
            
            self.log_message("\n一键处理流程完成！")
            self.log_message("生成的文件：")
            self.log_message(f"1. 域名统计结果：{domain_count_file}")
            self.log_message(f"2. 合并规则结果：{merged_rules_file}")
            self.log_message(f"3. 精简规则结果：{optimized_rules_file}")
            
            self.root.after(0, lambda: messagebox.showinfo("完成", "一键处理流程完成！"))
            
        except Exception as e:
            self.log_message(f"\n错误: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("错误", f"处理过程中出现错误:\n{str(e)}"))
        finally:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.process_button.config(state='normal'))
            
    def start_processing(self):
        """开始处理"""
        # 在新线程中执行处理，避免界面冻结
        threading.Thread(target=self.process_thread, daemon=True).start()

def main():
    root = tk.Tk()
    app = OneClickProcessor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
