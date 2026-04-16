import threading
import sys
import time
import math

class Spinner:
    def __init__(self, obj, message="", countdown=None, interval=0.15):
        self.obj = obj
        self.countdown = float(countdown) if countdown is not None else None
        self.message = message
        self.interval = interval
        self.chars = "⣾⣽⣻⢿⡿⣟⣯⣷"
        self.running = False
        self.thread = None
        self._idx = 0
        self._msg_index = 0  # 记录已输出的消息索引
        self._start_time = None

    def _spin(self):
        try:
            while self.running:
                # 先清除当前 spinner 行，再输出消息
                self.clear_spinner_line()
                # 只输出新消息（从上次索引开始）
                with self.obj._msg_lock:
                    for msg in self.obj.stdout_msg[self._msg_index:]:
                        sys.stdout.write(f'{msg}\n')
                        sys.stdout.flush()
                    
                    # 更新已输出消息的索引
                    self._msg_index = len(self.obj.stdout_msg)

                # 更新 spinner 字符
                char = self.chars[self._idx % len(self.chars)]
                
                # 显示 spinner + 倒计时
                if self.countdown is not None:
                    elapsed = time.time() - self._start_time
                    remaining = max(0, self.countdown - elapsed)
                    tips = f"{self.message} {math.ceil(remaining)}s"
                else:
                    tips = self.message

                sys.stdout.write(f'\r{char} {tips}')
                sys.stdout.flush()

                time.sleep(self.interval)
                self._idx += 1
        except Exception as e:
            # 可以记录错误，但至少不要静默失败
            import traceback
            sys.stderr.write(f"\nSpinner error: {e}\n")
            traceback.print_exc()

    def clear_spinner_line(self, extra=20):
        # 清除 spinner 行
        # sys.stdout.write('\r' + ' ' * (len(self.message) + extra) + '\r')
        sys.stdout.write('\033[2K\r')  #  ANSI 转义序列 清除整行 + 回车
        sys.stdout.flush()        

    def start(self):
        self.running = True
        self._start_time = time.time()
        sys.stdout.write('\033[?25l')  # 隐藏光标
        sys.stdout.flush()
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        self.clear_spinner_line()
        sys.stdout.write('\033[?25h')  # 显示光标
        sys.stdout.flush()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()