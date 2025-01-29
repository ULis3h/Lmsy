import requests
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import concurrent.futures
import time
from datetime import datetime
import os

class DomainScanner:
    def __init__(self, domain, subdomain_dict_path, max_workers=10):
        self.domain = domain
        self.subdomain_dict_path = subdomain_dict_path
        self.max_workers = max_workers
        self.subdomains = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def load_subdomain_dict(self):
        """加载子域名字典"""
        with open(self.subdomain_dict_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
            
    def check_subdomain(self, subdomain):
        """检查子域名是否存在"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            dns.resolver.resolve(full_domain, 'A')
            self.subdomains.add(full_domain)
            print(f"发现子域名: {full_domain}")
        except:
            pass
            
    def scan_subdomains(self):
        """并发扫描子域名"""
        print(f"开始扫描 {self.domain} 的子域名...")
        subdomains_list = self.load_subdomain_dict()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(self.check_subdomain, subdomains_list)
            
        return self.subdomains

class SMSPageCrawler:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file
        self.visited_urls = set()
        self.sms_pages = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def has_sms_features(self, html_content):
        """检查页面是否包含短信验证码相关特征"""
        sms_keywords = [
            '短信验证码', '验证码', 'SMS', 'verification code',
            'mobile verification', '手机验证', '发送验证码',
            'send code', '获取验证码'
        ]
        
        phone_patterns = [
            'type="tel"',
            'phone',
            'mobile',
            'tel',
            '手机',
            '电话'
        ]
        
        content_lower = html_content.lower()
        has_sms_keyword = any(keyword.lower() in content_lower for keyword in sms_keywords)
        has_phone_input = any(pattern.lower() in content_lower for pattern in phone_patterns)
        
        return has_sms_keyword and has_phone_input
    
    def extract_links(self, html_content, base_url):
        """提取页面中的所有链接"""
        soup = BeautifulSoup(html_content, 'html.parser')
        links = set()
        base_domain = urlparse(base_url).netloc
        
        for a_tag in soup.find_all('a', href=True):
            url = urljoin(base_url, a_tag['href'])
            parsed_url = urlparse(url)
            if parsed_url.netloc == base_domain and parsed_url.scheme in ['http', 'https']:
                links.add(url)
                
        return links
    
    def save_url(self, url):
        """保存发现的URL到文件"""
        with open(self.output_file, 'a', encoding='utf-8') as f:
            f.write(f"{url}\n")
    
    def crawl_domain(self, domain):
        """爬取单个域名的所有页面"""
        start_urls = [f'https://{domain}', f'http://{domain}']
        urls_to_visit = set(start_urls)
        
        while urls_to_visit:
            current_url = urls_to_visit.pop()
            
            if current_url in self.visited_urls:
                continue
                
            try:
                print(f"正在爬取: {current_url}")
                response = requests.get(current_url, headers=self.headers, timeout=10)
                response.raise_for_status()
                
                self.visited_urls.add(current_url)
                
                if self.has_sms_features(response.text):
                    self.sms_pages.add(current_url)
                    self.save_url(current_url)
                    print(f"找到短信验证码页面: {current_url}")
                
                new_links = self.extract_links(response.text, current_url)
                urls_to_visit.update(new_links - self.visited_urls)
                
                time.sleep(1)  # 避免请求过于频繁
                
            except Exception as e:
                print(f"爬取 {current_url} 时出错: {str(e)}")
    
    def crawl_all(self):
        """爬取所有域名"""
        for domain in self.domains:
            print(f"\n开始爬取域名: {domain}")
            self.crawl_domain(domain)
        
        return len(self.sms_pages)

def main():
    # 配置参数
    main_domain = "qq.com"  # 替换为目标域名
    subdomain_dict_path = "subdomains.txt"  # 子域名字典文件路径
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"sms_pages_{timestamp}.txt"
    
    # 1. 扫描子域名
    scanner = DomainScanner(main_domain, subdomain_dict_path)
    subdomains = scanner.scan_subdomains()
    print(f"\n发现 {len(subdomains)} 个子域名")
    
    # 将扫描到的子域名保存到文件
    with open(f"subdomains_{timestamp}.txt", 'w', encoding='utf-8') as f:
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")
    
    # 2. 爬取页面并查找短信验证码
    crawler = SMSPageCrawler(subdomains, output_file)
    total_sms_pages = crawler.crawl_all()
    
    # 3. 输出结果摘要
    print("\n扫描完成!")
    print(f"总共扫描域名数: {len(subdomains)}")
    print(f"发现短信验证码页面数: {total_sms_pages}")
    print(f"结果已保存到: {output_file}")

if __name__ == "__main__":
    main()