#ifndef DEFERRED_SIGNALS_H
#define DEFERRED_SIGNALS_H

#include <QVector>
#include <utility>

// ============================================================================
// DeferredSignalQueue — 持锁期间延迟信号缓冲（EapProcess / UdpProcess 共用）
//
// 背景：工作线程在持有 m_mutex 的临界区内不能直接 emit（若未来把连接方式
// 改为 DirectConnection，会在槽逻辑中锁重入/死锁）。惯例是"持锁期间只缓冲
// 信号描述，解锁后统一发出"，且必须按产生顺序发射以保持日志与状态变更顺序。
//
// 本模板只提供队列机制（append / flush / clear / isEmpty），信号的具体结构
// 与发射逻辑仍由各进程自己的 PendingSignal 类型与 flush 回调决定。
//
// 线程性：非线程安全。约定与所属 m_mutex 一起使用（持锁追加、解锁后 flush）。
// ============================================================================

template <typename Signal>
class DeferredSignalQueue {
public:
    void append(Signal s) { m_pending.append(std::move(s)); }
    void clear()    { m_pending.clear(); }
    bool isEmpty() const { return m_pending.isEmpty(); }

    // 按产生顺序逐个回调 emitOne(sig)，随后清空。调用者须【不】持有 m_mutex。
    template <typename Emitter>
    void flush(Emitter&& emitOne) {
        for (const auto& sig : m_pending)
            emitOne(sig);
        m_pending.clear();
    }

private:
    QVector<Signal> m_pending;
};

#endif // DEFERRED_SIGNALS_H
