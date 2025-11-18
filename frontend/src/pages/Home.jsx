import React from "react";
import Header from "../components/Header.jsx";

/**
 * Home component
 *
 * Role in flow:
 * - Serves as the main landing page for authenticated users. The `Header`
 *   component typically renders navigation and sign-out actions that rely on
 *   cookie-based authentication (HttpOnly `token` cookie).
 * - When signed in, AppContext uses the `token` cookie to fetch user profile
 *   data from the backend. The Home page itself is a simple wrapper for that content.
 */
const Home = () => {
  return (
    <div className="">
      <Header />
    </div>
  );
};

export default Home;
