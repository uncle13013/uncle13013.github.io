---
layout: page
title: "Blog"
permalink: /blog/
---

# Blog Posts

Welcome to my blog where I share insights, tutorials, and thoughts on DevSecOps, cloud security, and automation.

## Recent Posts

<ul>
  {% for post in site.posts %}
    <li style="margin-bottom: 30px; list-style: none;">
      <h3><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h3>
      <p style="color: #666; font-size: 0.9em;">{{ post.date | date: "%B %d, %Y" }}</p>
      {% if post.tags.size > 0 %}
        <p style="margin: 5px 0;">
          {% for tag in post.tags %}
            <span style="background: #f0f0f0; padding: 2px 6px; margin-right: 5px; border-radius: 3px; font-size: 0.8em;">{{ tag }}</span>
          {% endfor %}
        </p>
      {% endif %}
      <p>{{ post.excerpt | strip_html | truncatewords: 40 }}</p>
      <p><a href="{{ post.url | relative_url }}" class="btn">Read more →</a></p>
    </li>
  {% endfor %}
</ul>

---

*Want to discuss any of these topics? Feel free to [reach out](/contact/) - I'd love to hear from you!*
A comprehensive series on implementing zero trust architecture in modern cloud environments.

### "Container Security Fundamentals"
Everything you need to know about securing containers from development to production.

### "Infrastructure as Code Security"
Best practices for building security into your IaC workflows and templates.

---

*Subscribe to stay updated with my latest posts and insights!*
