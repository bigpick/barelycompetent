class TocScroller {
  static init() {
    if(document.querySelector('.tocLinks')) {
      this.tocLinks = document.querySelectorAll('.tocLinks a');
      this.tocLinks.forEach(link => link.classList.add('transition', 'duration-200'))
      this.headers = Array.from(this.tocLinks).map(link => {
        return document.querySelector(`#${link.href.split('#')[1]}`);
      })
      console.log(this.headers);
      this.ticking = false;
      window.addEventListener('scroll', (e) => {
        this.onScroll()
      })
    }
  }

  static onScroll() {
    if(!this.ticking) {
      requestAnimationFrame(this.update.bind(this));
      this.ticking = true;
    }
  }

  static update() {
    this.activeHeader ||= this.headers[0];
    var activeIndex = this.headers.findIndex((header) => {
      return header.getBoundingClientRect().top > 180;
    });
    if(activeIndex == -1) {
      activeIndex = this.headers.length - 1;
    } else if(activeIndex > 0) {
      activeIndex--;
    }
    var active = this.headers[activeIndex];
    if(active !== this.activeHeader) {
      this.activeHeader = active;
      this.tocLinks.forEach(link => link.classList.remove('text-active'));
      this.tocLinks[activeIndex].classList.add('text-active');
    }
    this.ticking = false;
  }
}

document.addEventListener('DOMContentLoaded', function(e) {
  TocScroller.init();
})
