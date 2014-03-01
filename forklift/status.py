import sys
from time import time

class NullStatus:
    WAITING = 0
    BACKING_UP = 1
    RESTORING = 2

    def __init__(self):
        self.mode = 0
        self.oldmode = 0
        self.t_bytes_u = 0
        self.t_bytes_d = 0
        self.t_chunks_u = 0
        self.t_chunks_d = 0
        self.files_d = 0
        self.bytes_d = 0
        self.chunks_d = 0
        self.bytes = 0
        self.files = 0
        self.dirs = 0
        self.chunks = 0
        self.printverbose = False
        self.text = 'WAITING'

        self.dl_stats = [(time(),0)] # (time(), t_bytes_d)
        self.ul_stats = [(time(),0)]
        self.index5s = 0 # index which points to 5 secs ago in stats

    def update_speed(self):
        t = time()
        self.dl_stats.append((t, self.t_bytes_d))
        self.ul_stats.append((t, self.t_bytes_u))
        while t - self.dl_stats[self.index5s][0] > 5 \
            and len(self.dl_stats) - self.index5s > 2:
            self.index5s += 1
        #    self.ul_stats.pop(0)

    def update(self):
        self.update_speed()

    def wait(self, text):
        if self.mode != self.WAITING:
            self.oldmode = self.mode
        self.mode = self.WAITING
        self.text = text
        self.update()

    def unwait(self):
        self.mode = self.oldmode
        self.text = 'WAITING'
        self.update()

    def verbose(self, text):
        if self.printverbose:
            self.println(unicode(text))

    def println(self, text):
        print(unicode(text))

    def end(self):
        pass

    def speed_str(self, bytesnow, bytesthen, timethen):
        try:
            return '%.0f KB/s' % \
                   ((bytesnow - bytesthen) / 1024.00 /
                    (time() - timethen), )
        except ZeroDivisionError:
            return 'inf KB/s'

    def up_speed_str(self):
        (t, b) = self.ul_stats[self.index5s]
        return self.speed_str(self.t_bytes_u, b, t)

    def down_speed_str(self):
        (t, b) = self.dl_stats[self.index5s]
        return self.speed_str(self.t_bytes_d, b, t)

class LogStatus(NullStatus):
    pass

class ConsoleStatus(NullStatus):

    def update(self):
        if self.mode == self.BACKING_UP:
            spinner = ['[   ]','[>  ]','[>> ]','[>>>]','[ >>]','[  >]']
            spinner = spinner[self.chunks % len(spinner)]
            sys.stdout.write(' ' + spinner + ' ')
            sys.stdout.write('%.2f MB up %s' %
                             (self.t_bytes_u / 1024.00 / 1024.00,
                              self.up_speed_str()))
            sys.stdout.write('   total: %.2f MB %d chunks' %
                             (self.bytes / 1024.00 / 1024.00,
                              self.chunks))
            sys.stdout.write('\r')
            sys.stdout.flush()
        elif self.mode == self.RESTORING:
            spinner = ['net','Net','NEt','NET','nET','neT']
            spinner = spinner[self.t_chunks_d % len(spinner)]
            percentbar = '>' * 80 
            if self.bytes == 0:
                percentbar = '#' * 80
                percent = 100
            else:
                percent = int(self.bytes_d * 100 / self.bytes)
                if percent > 100:
                    percent = 100
                percentbar = percentbar + unicode(percent)
            if int(percent*10/100) == 0:
                percentbar = ' ' * 10
            else:
                percentbar = percentbar[-(percent*10/100):]
                percentbar += ' ' * (10-len(percentbar))
            sys.stdout.write('[' + percentbar + '] ')
            sys.stdout.write('%.2f/%.2fMB %d/%d files ' %
                             (self.bytes_d / 1024.00 / 1024.00,
                              self.bytes / 1024.00 / 1024.00,
                              self.files_d,
                              self.files))
            sys.stdout.write('(%s %d MB, %s)' %
                             (spinner,
                              self.t_bytes_d / 1024.00 / 1024.00,
                              self.down_speed_str()))

            sys.stdout.write('\r')
            sys.stdout.flush()
        elif self.mode == self.WAITING:
            sys.stdout.write('  %s  |' % (self.text, ) )
            sys.stdout.write('\r')
            sys.stdout.flush()
        self.update_speed()

    def end(self):
        sys.stdout.write(' ' * 78)
        sys.stdout.write('\r')
        sys.stdout.write('Summary:\n')
        sys.stdout.write('--------\n')
        sys.stdout.write('Total MB uploaded this session:    %.2f\n'
                         'Total MB downloaded this session:  %.2f\n'
                         'Total files:                       %d\n'
                         'Total size in MB:                  %.2f\n' %
                         (self.t_bytes_u / 1024.00 / 1024.00,
                          self.t_bytes_d / 1024.00 / 1024.00,
                          self.files,
                          self.bytes / 1024.00 / 1024.00))
        sys.stdout.flush()


    def println(self, text):
        print((' ' * 78) + '\r' + unicode(text))
        self.update()
    
