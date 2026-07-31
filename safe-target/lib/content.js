// Static site content. No credentials, no database, no user input.

export const featured = [
  { name: "House Latte", description: "Espresso with steamed milk" },
  { name: "Cold Brew", description: "Slow-steeped for 18 hours" },
  { name: "Matcha Tea", description: "Stone-ground green tea" },
];

export const hours = [
  { day: "Monday", open: "7:00 AM", close: "6:00 PM" },
  { day: "Tuesday", open: "7:00 AM", close: "6:00 PM" },
  { day: "Weekend", open: "8:00 AM", close: "4:00 PM" },
];

export const menu = [
  {
    category: "Coffee",
    items: [
      { name: "House Latte", price: "$4.50" },
      { name: "Cold Brew", price: "$4.00" },
    ],
  },
  {
    category: "Pastries",
    items: [
      { name: "Butter Croissant", price: "$3.25" },
      { name: "Blueberry Muffin", price: "$3.00" },
    ],
  },
];

export const contact = {
  email: "hello@brewandbytes.example",
  phone: "+1 (555) 010-2040",
  address: "42 Roasters Lane, Springfield",
};
