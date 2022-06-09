use core::task::Waker;

pub struct WakerRegistry {
    wakers: Vec<Waker>,
}

impl WakerRegistry {
    pub fn new() -> Self {
        Self { wakers: Vec::new() }
    }

    pub fn awake_all(&mut self) {
        while let Some(waker) = self.wakers.pop() {
            waker.wake()
        }
    }

    pub fn register(&mut self, waker: Waker) {
        // if self.wakers.iter().any(|w| waker.will_wake(w)) {
        //     return;
        // }
        self.wakers.push(waker)
    }
}
