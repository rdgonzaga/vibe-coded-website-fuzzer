import { contact } from "../../lib/content";

export default function Contact() {
  return (
    <main>
      <h1>Visit Us</h1>
      <p>Email: {contact.email}</p>
      <p>Phone: {contact.phone}</p>
      <p>Address: {contact.address}</p>
    </main>
  );
}
