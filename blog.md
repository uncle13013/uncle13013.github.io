---
layout: page
title: "Blog"
permalink: /blog/
---

# Blog

Thoughts and notes on security, automation, and cloud technologies.

## Recent Posts

<ul>
  {% for post in site.posts %}
    <li style="margin-bottom: 20px; list-style: none;">
      <h3><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h3>
      <p style="color: #666; font-size: 0.9em;">{{ post.date | date: "%B %d, %Y" }}</p>
      <p>{{ post.excerpt | strip_html | truncatewords: 30 }}</p>
    </li>
  {% endfor %}
</ul>

---

*Have thoughts on any of these topics? Feel free to [reach out](/contact/).*
A comprehensive series on implementing zero trust architecture in modern cloud environments.

### "Container Security Fundamentals"
Everything you need to know about securing containers from development to production.

### "Infrastructure as Code Security"
Best practices for building security into your IaC workflows and templates.

---

*Subscribe to stay updated with my latest posts and insights!*
